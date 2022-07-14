FROM rust:1.62.0-slim-buster

ARG features=""

WORKDIR /app

COPY Cargo.* ./
COPY ./dexios ./dexios
COPY ./dexios-core ./dexios-core

RUN cargo install --bin dexios --path ./dexios ${features:+--features=${features}} \
  && rm -rf ./dexios* Cargo.*

VOLUME ["/data"]

WORKDIR /data

ENTRYPOINT ["/usr/local/cargo/bin/dexios"]

