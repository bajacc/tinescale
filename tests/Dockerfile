FROM lukemathwalker/cargo-chef:latest-rust-1 AS chef
WORKDIR /app

FROM chef AS planner
COPY ./src ./src
COPY ./Cargo.lock .
COPY ./Cargo.toml .
COPY ./build.rs .
COPY ./proto ./proto
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS builder 
COPY --from=planner /app/recipe.json recipe.json
RUN cargo chef cook --release --recipe-path recipe.json
RUN apt-get update && apt-get install -y protobuf-compiler && rm -rf /var/lib/apt/lists/*
COPY ./src ./src
COPY ./Cargo.lock .
COPY ./Cargo.toml .
COPY ./build.rs .
COPY ./proto ./proto
RUN cargo build --release

FROM debian:bookworm-slim AS runtime
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends \
    socat \
    iproute2 \
    ca-certificates \
    iputils-ping \
    traceroute \
    curl \
    wget \
    iproute2 \
    tcpdump \
    wireguard-tools \
    dnsutils \
    net-tools \
 && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/tinescale /usr/local/bin/
COPY tests/entrypoint.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/entrypoint.sh

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]