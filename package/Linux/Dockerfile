FROM mcr.microsoft.com/powershell:debian-bullseye-slim
LABEL maintainer "Devolutions Inc."

ADD webapp /usr/share/devolutions-gateway/webapp

WORKDIR /usr/bin

RUN apt-get update
RUN apt-get install -y --no-install-recommends ca-certificates curl
RUN rm -rf /var/lib/apt/lists/*

COPY devolutions-gateway .

EXPOSE 8080
EXPOSE 10256

ENTRYPOINT [ "./devolutions-gateway" ]
