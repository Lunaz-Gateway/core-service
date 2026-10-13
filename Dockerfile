# syntax=docker/dockerfile:1.7
FROM rust:1.98.1-slim-bookworm AS build
WORKDIR /src
RUN apt-get update && apt-get install -y --no-install-recommends build-essential pkg-config protobuf-compiler \
    && rm -rf /var/lib/apt/lists/*
# Cache dependencies: build a dummy main first
COPY Cargo.toml Cargo.lock ./
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    mkdir src && echo 'fn main() {}' > src/main.rs && cargo build --release --locked
COPY src ./src
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    rm -rf target/release/lunaz-core target/release/deps/lunaz_core-* target/release/.fingerprint/lunaz-core-* \
    && cargo build --release --locked \
    && cp target/release/lunaz-core /lunaz-core && ldd /lunaz-core \
    && mkdir /data

FROM gcr.io/distroless/cc-debian12:nonroot
LABEL org.opencontainers.image.title="lunaz-core"
COPY --from=build /lunaz-core /lunaz-core
COPY --from=build --chown=65532:65532 /data /data
ENV LUNAZ_DB=/data/lunaz.db LUNAZ_BIND=0.0.0.0:8080 LUNAZ_NETWORK=main
VOLUME /data
EXPOSE 8080
USER 65532:65532
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 CMD ["/lunaz-core", "healthcheck"]
ENTRYPOINT ["/lunaz-core"]
