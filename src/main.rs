use anyhow::Result;
use axum::{
    extract::Path,
    response::{Html, IntoResponse, Redirect},
    routing::get,
    Router,
};
use axum_server::tls_rustls::RustlsConfig;
use dotenv::dotenv;
use hmac::{Hmac, Mac};
use lapin::{options::*, types::FieldTable, BasicProperties, Connection, ConnectionProperties};
use sha2::Sha256;
use std::{env, path::PathBuf};
use tera::Tera;
use tokio::signal;
use tracing::{error, info, warn};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

type HmacSha256 = Hmac<Sha256>;

lazy_static::lazy_static! {
    pub static ref TEMPLATES: Tera = {
        match Tera::new("templates/**/*.html") {
            Ok(t) => t,
            Err(e) => {
                panic!("Error parsing templates: {}", e);
            }
        }
    };
}

// Configuration struct to hold environment variables
#[derive(Debug)]
struct Config {
    hmac_secret: String,
    amqp_url: String,
    host: String,
    port: u16,
    allowed_schemes: Vec<String>,
    use_https: bool,
    cert_path: Option<PathBuf>,
    key_path: Option<PathBuf>,
}

impl Config {
    fn from_env() -> Result<Self, env::VarError> {
        // Load .env file
        dotenv().ok();

        let schemes = env::var("ALLOWED_SCHEMES")
            .unwrap_or_else(|_| "http,https".to_string())
            .split(',')
            .map(|s| s.trim().to_string())
            .collect();

        let use_https = env::var("USE_HTTPS")
            .unwrap_or_else(|_| "false".to_string())
            .parse()
            .unwrap_or(false);

        let cert_path = env::var("TLS_CERT_PATH").ok().map(PathBuf::from);
        let key_path = env::var("TLS_KEY_PATH").ok().map(PathBuf::from);

        Ok(Config {
            hmac_secret: env::var("HMAC_SECRET")?,
            amqp_url: env::var("AMQP_URL").unwrap_or_else(|_| "amqp://localhost".to_string()),
            host: env::var("HOST").unwrap_or_else(|_| "127.0.0.1".to_string()),
            port: env::var("PORT")
                .unwrap_or_else(|_| "3000".to_string())
                .parse()
                .expect("PORT must be a number"),
            allowed_schemes: schemes,
            use_https,
            cert_path,
            key_path,
        })
    }
}

#[derive(serde::Serialize)]
struct LinkTrackingData {
    destination_url: String,
    timestamp: chrono::DateTime<chrono::Utc>,
    success: bool,
}

async fn verify_signature(url: &str, signature: &str, secret: &[u8]) -> bool {
    let mut mac = HmacSha256::new_from_slice(secret)
        .expect("HMAC initialization should not fail with valid key length");

    mac.update(url.as_bytes());

    let signature_bytes = hex::decode(signature).unwrap_or_default();

    mac.verify_slice(&signature_bytes).is_ok()
}

async fn send_to_rabbitmq(
    conn: &Connection,
    tracking_data: &LinkTrackingData,
) -> Result<(), Box<dyn std::error::Error>> {
    let channel = conn.create_channel().await?;

    info!("Declaring RabbitMQ queue 'link_tracking'");
    channel
        .queue_declare(
            "link_tracking",
            QueueDeclareOptions::default(),
            FieldTable::default(),
        )
        .await?;

    let payload = serde_json::to_string(&tracking_data)?;

    info!("Publishing tracking data to RabbitMQ");
    channel
        .basic_publish(
            "",
            "link_tracking",
            BasicPublishOptions::default(),
            payload.as_bytes(),
            BasicProperties::default(),
        )
        .await?;

    Ok(())
}

async fn handle_tracked_link(Path((url, signature)): Path<(String, String)>) -> impl IntoResponse {
    info!("Processing tracked link request for URL: {}", url);

    let config = Config::from_env().expect("Failed to load configuration");

    let is_valid = verify_signature(&url, &signature, config.hmac_secret.as_bytes()).await;

    let mut context = tera::Context::new();
    context.insert("url", &url);

    if is_valid {
        info!("Valid signature for URL: {}", url);

        let tracking_data = LinkTrackingData {
            destination_url: url.clone(),
            timestamp: chrono::Utc::now(),
            success: true,
        };

        if let Ok(conn) =
            Connection::connect(&config.amqp_url, ConnectionProperties::default()).await
        {
            if let Err(e) = send_to_rabbitmq(&conn, &tracking_data).await {
                error!("Failed to send to RabbitMQ: {}", e);
            }
        } else {
            error!("Failed to connect to RabbitMQ");
        }

        Redirect::temporary(&url).into_response()
    } else {
        warn!("Invalid signature detected for URL: {}", url);

        let rendered = TEMPLATES
            .render("error.html", &context)
            .unwrap_or_else(|e| {
                error!("Template rendering error: {}", e);
                "Error: Invalid Link".to_string()
            });

        Html(rendered).into_response()
    }
}

async fn handle_default() -> impl IntoResponse {
    info!("Handling default route request");

    let context = tera::Context::new();
    let rendered = TEMPLATES
        .render("welcome.html", &context)
        .unwrap_or_else(|e| {
            error!("Template rendering error: {}", e);
            "Welcome to Link Tracker".to_string()
        });

    Html(rendered)
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| format!("{}=debug", env!("CARGO_CRATE_NAME")).into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    info!("Starting Link Tracker service");

    // Load configuration
    let config = Config::from_env().expect("Failed to load configuration");
    info!(
        "Configuration loaded successfully with allowed schemes: {:?}",
        config.allowed_schemes
    );

    // Build router
    let app = Router::new()
        .route("/track/{url}/{signature}", get(handle_tracked_link))
        .fallback(handle_default);

    // Start server based on configuration
    let addr = format!("{}:{}", config.host, config.port);

    if config.use_https {
        info!("Starting HTTPS server");

        // Initialize crypto provider
        let _ = rustls::crypto::ring::default_provider().install_default();

        // Check for required TLS files
        let cert_path = config
            .cert_path
            .expect("TLS_CERT_PATH must be set when USE_HTTPS is true");
        let key_path = config
            .key_path
            .expect("TLS_KEY_PATH must be set when USE_HTTPS is true");

        // configure certificate and private key used by https
        let config = RustlsConfig::from_pem_file(cert_path, key_path).await?;

        info!("HTTPS server running on https://{}", addr);

        // Start HTTPS server
        axum_server::bind_rustls(addr.parse()?, config)
            .serve(app.into_make_service())
            .await?;
    } else {
        info!("Starting HTTP server");

        let listener = tokio::net::TcpListener::bind(&addr).await?;

        info!("HTTP server running on http://{}", addr);

        axum::serve(listener, app)
            .with_graceful_shutdown(shutdown_signal())
            .await?;
    };

    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {
            info!("HTTP server terminate with ctrl_c");
        },
        _ = terminate => {
            info!("HTTP server terminate");
        },
    }
}
