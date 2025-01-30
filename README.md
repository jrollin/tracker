# Rust tracking

## Why this app

MVP to check axum capabilities

Usecase :

Generate URL with redirect URL as param and and hashmac signature

App server :

- app handle route with URL as param
- validate hashmac signature
- emit event to bus
- redirect to url

Templates html can be customized

## Stack

- Rust + Axum
- RabbitMQ

## Prerequisites

For local env without docker

```bash
cp .env.docker .env
```

## Config with no SSL

Update `.env` with your params

```text
USE_HTTPS=false
```

## Config with https

Generate ssl

```bash
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes
```

Update `.env` with your params

```text
USE_HTTPS=true                # Set to true to enable HTTPS
TLS_CERT_PATH=./certs/cert.pem # Required if USE_HTTPS is true
TLS_KEY_PATH=./certs/key.pem   # Required if USE_HTTPS is true
```

## Run with docker

Start stack

```bash
docker compose up --build
```

> no need for --build argument if done once and no code change

App URL

http://localhost:3000

Ui RabbitMQ

http://localhost:15672 (guest/guest)

Logs

```bash
docker compose logs -f app
```

Rabbitmq queues

```bash
docker compose exec rabbitmq rabbitmqctl list_queues
```

## Generate URL with signature

```bash
cargo run --example generate
```
