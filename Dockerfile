FROM rust:1.62.0-slim-buster

WORKDIR /app

COPY Cargo.* ./
COPY Cargo.toml ./Cargo.source.toml

RUN sed -e 's/"dexios-gui",//' Cargo.source.toml > Cargo.toml \
  && cat Cargo.toml

COPY ./dexios ./dexios
COPY ./dexios-domain ./dexios-domain
COPY ./dexios-core ./dexios-core

RUN cargo install --bin dexios --path ./dexios \
  && rm -rf ./dexios* Cargo.*

VOLUME ["/data"]

WORKDIR /data

ENTRYPOINT ["/usr/local/cargo/bin/dexios"]

