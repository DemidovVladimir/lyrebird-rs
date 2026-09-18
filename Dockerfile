# lyrebird-rs: drop-in `lyrebird` binary (Rust port).
#   docker build -t lyrebird-rs .
FROM rust:1.91-bookworm AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --release --locked --bin lyrebird \
 && strip target/release/lyrebird

FROM debian:bookworm-slim
COPY --from=build /src/target/release/lyrebird /usr/local/bin/lyrebird
USER nobody
ENTRYPOINT ["/usr/local/bin/lyrebird"]
