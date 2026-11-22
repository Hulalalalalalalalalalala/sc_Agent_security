FROM rust:1.80-alpine AS builder
WORKDIR /src
COPY Cargo.toml /src/
COPY src /src/src
RUN cargo build --release

FROM alpine:3.20
COPY --from=builder /src/target/release/rust-lct-agent /usr/local/bin/rust-lct-agent
ENTRYPOINT ["/usr/local/bin/rust-lct-agent"]
