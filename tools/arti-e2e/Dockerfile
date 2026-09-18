# Arti 2.6.0 + lyrebird-rs as its managed transport.
# Build context: the repo root. See tools/arti-e2e/run.sh.
ARG ARTI_VERSION=2.6.0

FROM rust:1.91-bookworm AS arti
ARG ARTI_VERSION
RUN apt-get update \
 && apt-get install -y --no-install-recommends libssl-dev libsqlite3-dev pkg-config \
 && rm -rf /var/lib/apt/lists/*
RUN cargo install arti --version "${ARTI_VERSION}" --locked --features http-connect \
 && strip /usr/local/cargo/bin/arti

FROM rust:1.91-bookworm AS lyrebird
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --release --locked --bin lyrebird && strip target/release/lyrebird

FROM debian:bookworm-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends libssl3 libsqlite3-0 curl ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --system --home-dir /var/lib/arti --create-home --shell /usr/sbin/nologin arti
COPY --from=arti /usr/local/cargo/bin/arti /usr/local/bin/arti
COPY --from=lyrebird /src/target/release/lyrebird /usr/local/bin/lyrebird
COPY tools/arti-e2e/entrypoint.sh /usr/local/bin/arti-e2e
USER arti
ENTRYPOINT ["/usr/local/bin/arti-e2e"]
