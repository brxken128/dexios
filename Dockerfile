FROM rust:1.62.0-slim-buster

WORKDIR /app

COPY Cargo.* ./
COPY ./dexios ./dexios
COPY ./dexios-core ./dexios-core

RUN cargo build --bin dexios --release --locked \
  && rm -rf ./dexios* Cargo.*

ENTRYPOINT ["/app/target/release/dexios"]

