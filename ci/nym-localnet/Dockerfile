# syntax=docker/dockerfile:1
#
# A local Nym mixnet for CI (docs/09-transport.md §1, X16 tier 2):
# nym-node at the release whose crates Enclave pins (1.21.5), patched to
# run with no blockchain (offline.patch: with ENCLAVE_NYM_OFFLINE=1 it
# skips the network-monitor and chain-watcher queries and the initial
# network fetch; --local lets it route between private addresses), plus
# the nym-api stand-in (one static file, the key-rotation information a
# client asks for) and the topology builder.
#
#   docker build -f ci/nym-localnet/Dockerfile -t enclave-nym-localnet ci/nym-localnet
#
# ops/compose/compose.localnet.yml runs it: three mix nodes, a gateway,
# the stand-in and a one-shot topology writer.

ARG RUST_IMAGE=rust:1.94.1-slim-bookworm@sha256:cf9dd0ec73e75f827fe59123fff9dc65af1a1c8363c3c31ee8d7f8ad0b6a5fb2
ARG RUNTIME_IMAGE=python:3.13-slim-bookworm@sha256:5024f48ba9441d4b13a95d3945abc6365538e3a31109833367a1923523c6efed
ARG NYM_TAG=nym-binaries-v2026.16-como

FROM ${RUST_IMAGE} AS build
ARG NYM_TAG
ENV CARGO_HOME=/cargo CARGO_INCREMENTAL=0 CARGO_TERM_COLOR=never
RUN apt-get update \
 && apt-get install -y --no-install-recommends git ca-certificates curl pkg-config libssl-dev build-essential \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /src
RUN git clone --depth 1 --branch "${NYM_TAG}" https://github.com/nymtech/nym.git nym
COPY offline.patch /src/
RUN cd nym && git apply ../offline.patch
RUN --mount=type=cache,target=/cargo/registry \
    --mount=type=cache,target=/src/nym/target \
    cd nym && cargo build --release --locked -p nym-node \
 && cp target/release/nym-node /usr/local/bin/

FROM ${RUNTIME_IMAGE}
LABEL org.opencontainers.image.title="enclave-nym-localnet" \
      org.opencontainers.image.description="A local Nym mixnet for Enclave's CI (not for production)" \
      org.opencontainers.image.source="https://github.com/0xnullsect0r/enclave-messenger" \
      org.opencontainers.image.licenses="GPL-3.0-only"
COPY --from=build /usr/local/bin/nym-node /usr/local/bin/nym-node
COPY topology.py /usr/local/bin/enclave-localnet-topology
COPY api /srv/api
ENV ENCLAVE_NYM_OFFLINE=1
ENTRYPOINT ["/usr/local/bin/nym-node"]
