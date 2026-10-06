# Stage 1: Build binary
FROM rust:1.85-slim-bookworm AS builder
WORKDIR /usr/src/app

RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY ui ./ui

RUN cargo build --release --bins

# Stage 2: Runtime image with SoftHSM2
FROM debian:bookworm-slim AS runtime
WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    softhsm2 \
    libsofthsm2 \
    ca-certificates \
    curl \
    bash \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /var/lib/softhsm/tokens /app/scripts

COPY --from=builder /usr/src/app/target/release/arkion-rust-hsm-signing-service /app/
COPY --from=builder /usr/src/app/target/release/init_hsm /app/
COPY scripts/entrypoint.sh /app/scripts/entrypoint.sh

RUN chmod +x /app/scripts/entrypoint.sh /app/arkion-rust-hsm-signing-service /app/init_hsm

ENV PKCS11_LIB_PATH=/usr/lib/softhsm/libsofthsm2.so
ENV HSM_TOKEN_LABEL=arkion-token
ENV HSM_SLOT_INDEX=0
ENV HSM_USER_PIN=1234
ENV HSM_SO_PIN=1234
ENV HSM_SESSION_POOL_SIZE=4
ENV HSM_ACQUISITION_TIMEOUT_MS=5000
ENV HSM_OPERATION_TIMEOUT_MS=10000
ENV HSM_ECDSA_KEY_LABEL=arkion-intermediate-prod
ENV HSM_AES_KEY_LABEL=arkion-aes-key
ENV HOST=0.0.0.0
ENV PORT=8080

EXPOSE 8080

ENTRYPOINT ["/app/scripts/entrypoint.sh"]
