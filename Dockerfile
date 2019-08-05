FROM debian:buster-slim
LABEL maintainer "Devolutions Inc."

WORKDIR /opt/wayk

RUN apt-get update
RUN apt-get install -y --no-install-recommends libssl1.1
RUN rm -rf /var/lib/apt/lists/*

COPY devolutions-jet .

EXPOSE 8080

ENTRYPOINT [ "./devolutions-jet" ]
