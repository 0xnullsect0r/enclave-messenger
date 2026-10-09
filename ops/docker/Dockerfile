# syntax=docker/dockerfile:1
#
# Enclave's service images (docs/13-operators.md, ops/compose).
#
#   docker build -f ops/docker/Dockerfile --target server -t enclave-server .
#   docker build -f ops/docker/Dockerfile --target nym -t enclave-nym .
#
# `server` holds every service an operator's stack runs except the Nym
# sidecar: enclave-server, enclave-witness, enclave-front, enclave-relay,
# enclave-push-relay, enclave-admin and enclave-credgate (the foundation's
# credential gate, compose profile `foundation`; built without its
# dev-tickets feature). The compose file picks the binary
# per service. The runtime is distroless (no shell, no package manager) and
# runs as the unprivileged `nonroot` user.
#
# Reproducible: base images are pinned by digest, the toolchain by version,
# dependencies by Cargo.lock (--locked), and the build has fixed paths
# (/src, /cargo) and a fixed SOURCE_DATE_EPOCH, as in `cargo xtask repro`.
# Two builds of the same commit give the same binaries (CI job `repro`
# checks the binaries; `docker-build` builds the image).

ARG RUST_IMAGE=rust:1.94.1-slim-bookworm@sha256:cf9dd0ec73e75f827fe59123fff9dc65af1a1c8363c3c31ee8d7f8ad0b6a5fb2
ARG RUNTIME_IMAGE=gcr.io/distroless/cc-debian12:nonroot@sha256:9dac0a79194e45a7da0158a9c6da57b217585af0786db3845d1f0ec1a0dd182f

FROM ${RUST_IMAGE} AS build
ENV CARGO_HOME=/cargo \
    CARGO_INCREMENTAL=0 \
    CARGO_TERM_COLOR=never \
    SOURCE_DATE_EPOCH=1700000000 \
    RUSTUP_TOOLCHAIN=1.94.1 \
    RUSTFLAGS="--remap-path-prefix=/cargo=/cargo --remap-path-prefix=/src=/src"
WORKDIR /src
COPY . .
# The registry and target directory are caches (speed only; what is built
# depends only on the sources and Cargo.lock).
RUN --mount=type=cache,target=/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release --locked \
      -p enclave-server -p enclave-witness -p enclave-front \
      -p enclave-relay -p enclave-push-relay -p enclave-admin -p enclave-credgate \
 && mkdir -p /out \
 && cp target/release/enclave-server target/release/enclave-witness \
       target/release/enclave-front target/release/enclave-relay \
       target/release/enclave-push-relay target/release/enclave-admin \
       target/release/enclave-credgate /out/
# State directories, owned by `nonroot` (65532), so the named volumes
# mounted on them start out writable; key directories owner-only.
RUN cd /var/lib && mkdir -p enclave \
 && cd enclave && mkdir server public backups witness front relay credgate \
      keys witness-keys relay-keys push-keys credgate-keys \
 && chmod 0700 keys witness-keys relay-keys push-keys credgate-keys \
 && chown -R 65532:65532 /var/lib/enclave

FROM ${RUNTIME_IMAGE} AS server
LABEL org.opencontainers.image.title="enclave-server" \
      org.opencontainers.image.description="Enclave server, witness, front, call relay and push relay" \
      org.opencontainers.image.source="https://github.com/EnclaveChat/Enclave" \
      org.opencontainers.image.licenses="GPL-3.0-only"
COPY --from=build /out/ /usr/local/bin/
COPY --from=build --chown=65532:65532 /var/lib/enclave/ /var/lib/enclave/
USER nonroot:nonroot
# State and keys live in volumes under /var/lib/enclave; configuration in
# /etc/enclave. Nothing listens unless a service is started.
WORKDIR /var/lib/enclave
ENTRYPOINT ["/usr/local/bin/enclave-server"]
CMD ["run", "--config", "/etc/enclave/server.toml"]

# The Nym sidecar, from the separate nym/ workspace (its own Cargo.lock:
# nym-sdk and arti can't share one).
FROM ${RUST_IMAGE} AS build-nym
ENV CARGO_HOME=/cargo \
    CARGO_INCREMENTAL=0 \
    CARGO_TERM_COLOR=never \
    SOURCE_DATE_EPOCH=1700000000 \
    RUSTUP_TOOLCHAIN=1.94.1 \
    RUSTFLAGS="--remap-path-prefix=/cargo=/cargo --remap-path-prefix=/src=/src"
WORKDIR /src
COPY . .
RUN --mount=type=cache,target=/cargo/registry \
    --mount=type=cache,target=/src/nym/target \
    cd nym && cargo build --release --locked -p enclave-ingress-bin \
 && mkdir -p /out && cp target/release/enclave-ingress /out/
RUN mkdir -p /var/lib/enclave/ingress /var/lib/enclave/public \
 && chmod 0700 /var/lib/enclave/ingress \
 && chown -R 65532:65532 /var/lib/enclave

FROM ${RUNTIME_IMAGE} AS nym
LABEL org.opencontainers.image.title="enclave-nym" \
      org.opencontainers.image.description="Enclave's Nym ingress: a stack's mixnet client in front of its server" \
      org.opencontainers.image.source="https://github.com/EnclaveChat/Enclave" \
      org.opencontainers.image.licenses="GPL-3.0-only"
COPY --from=build-nym /out/ /usr/local/bin/
COPY --from=build-nym --chown=65532:65532 /var/lib/enclave/ /var/lib/enclave/
USER nonroot:nonroot
WORKDIR /var/lib/enclave
ENTRYPOINT ["/usr/local/bin/enclave-ingress"]
CMD ["run"]
