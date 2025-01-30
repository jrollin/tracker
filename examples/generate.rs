use anyhow::Result;
use dotenv::dotenv;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::env;
use urlencoding::encode;

type HmacSha256 = Hmac<Sha256>;

fn generate_signature(url: &str, secret: &str) -> String {
    let mut mac =
        HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC initialization failed");
    mac.update(url.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

fn main() -> Result<()> {
    dotenv().ok();

    let url = "https://example.com";

    let use_https = env::var("USE_HTTPS")?;
    let scheme = match use_https.as_str() {
        "true" => "https",
        _ => "http",
    };
    let secret = env::var("HMAC_SECRET")?;
    let signature = generate_signature(url, secret.as_str());
    println!(
        "Tracked URL: {}://localhost:3000/track/{}/{}",
        scheme,
        encode(url),
        signature
    );

    Ok(())
}
