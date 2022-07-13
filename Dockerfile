FROM rust:1.62.0-slim-buster

ARG features=""

WORKDIR /app

COPY Cargo.lock ./
COPY ./dexios ./

RUN cargo build --bin dexios --release --locked ${features:+--features=${features}} \
  && rm -rf ./dexios* Cargo.*

VOLUME ["/data"]

WORKDIR /data

ENTRYPOINT ["/app/target/release/dexios"]

