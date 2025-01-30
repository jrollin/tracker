FROM rust:1.83 as chef
# We only pay the installation cost once, 
# it will be cached from the second build onwards
RUN cargo install cargo-chef 
WORKDIR /app

FROM chef AS planner
COPY . .
RUN cargo chef prepare  --recipe-path recipe.json

# Build dependencies - this is the caching Docker layer!
FROM chef AS builder
COPY --from=planner /app/recipe.json recipe.json
RUN cargo chef cook --release --recipe-path recipe.json
COPY . .
RUN cargo build --release

# run 
FROM debian:bookworm-slim
WORKDIR /app
COPY --from=builder /app/target/release/rust-tracker .

# COPY certs/ /app/certs/

CMD ["./rust-tracker"]
