# syntax=docker/dockerfile:1.7
FROM rust:1.98.1-bookworm@sha256:93ce27a88655056a51dbdd8f5f2d7ddc071c7b0070fb288a37b5a285fc83971e AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock build.rs ./
COPY src ./src
COPY proto ./proto
COPY protocol ./protocol
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,target=/src/target,sharing=locked \
    cargo build --release --locked --bin openshell-kata --bin kata-kubernetes --bin kata-operator --bin kata-network --bin kata-runtime-guard --bin kata-node-intent --bin kata-network-inventory \
    && install -D target/release/openshell-kata /out/openshell-kata \
    && install -D target/release/kata-kubernetes /out/kata-kubernetes \
    && install -D target/release/kata-operator /out/kata-operator \
    && install -D target/release/kata-network /out/kata-network \
    && install -D target/release/kata-runtime-guard /out/kata-runtime-guard \
    && install -D target/release/kata-node-intent /out/kata-node-intent \
    && install -D target/release/kata-network-inventory /out/kata-network-inventory

FROM registry.k8s.io/kubectl@sha256:63e5e76b746bb8b891a94968d380736c035e768dab0d56ddad1f50c750a4be39 AS kubectl
FROM debian:bookworm-slim@sha256:3783cc01769c7b2b1b83a5c5ad96c815348e28ed7da68e2e3687004faa906251
RUN apt-get update && apt-get install -y --no-install-recommends openssh-client ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --uid 1000 --create-home --home-dir /home/openshell openshell \
    && install -d -o 1000 -g 1000 -m 700 /var/lib/openshell-kata /run/openshell-kata
COPY --from=build /out/ /usr/local/bin/
COPY --from=kubectl /bin/kubectl /usr/local/bin/kubectl
USER 1000:1000
ENTRYPOINT ["/usr/local/bin/openshell-kata"]
