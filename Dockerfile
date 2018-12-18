# build container

FROM rust:1-stretch as rust-build
LABEL maintainer "Devolutions Inc."

WORKDIR /opt/devolutions-jet

COPY ./Cargo.lock ./Cargo.lock
COPY ./Cargo.toml ./Cargo.toml
COPY ./jet-proto ./jet-proto
COPY ./src ./src

RUN cargo build --release

# production container

FROM debian:stretch-slim
LABEL maintainer "Devolutions Inc."

WORKDIR /opt/devolutions-jet

RUN apt-get update
RUN rm -rf /var/lib/apt/lists/*

COPY --from=rust-build /opt/devolutions-jet/target/release/devolutions-jet .

EXPOSE 8080

ENTRYPOINT [ "./devolutions-jet" ]
