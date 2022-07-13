FROM rust:1.62.0-slim-buster

ARG features=""

WORKDIR /app

COPY Cargo.* ./
COPY ./dexios ./dexios
# COPY ./dexios-core ./dexios-core

RUN cargo build --bin dexios --release --locked ${features:+--features=${features}} \
  && rm -rf ./dexios* Cargo.*

VOLUME ["/data"]

WORKDIR /data

ENTRYPOINT ["/app/target/release/dexios"]

