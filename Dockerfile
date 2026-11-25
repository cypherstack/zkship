# syntax=docker/dockerfile:1

FROM rust:1.94-slim-bookworm AS builder
WORKDIR /src

COPY zkship/Cargo.toml zkship/Cargo.lock ./
COPY zkship/zkb-core ./zkb-core
COPY zkship/zkb-session ./zkb-session
COPY zkship/zkb-wasm ./zkb-wasm
COPY zkship/zkb-relay ./zkb-relay
COPY zkship/zkb-cli ./zkb-cli
COPY zkship/zkb-bench ./zkb-bench

RUN cargo build --release --locked -p zkb-relay --bin zkb-relay

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 --no-create-home --shell /usr/sbin/nologin zkb

COPY --from=builder /src/target/release/zkb-relay /usr/local/bin/zkb-relay

USER 10001:10001
ENV ZKB_BIND_ADDR=0.0.0.0:8080
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD ["/usr/local/bin/zkb-relay", "--healthcheck"]

ENTRYPOINT ["/usr/local/bin/zkb-relay"]
