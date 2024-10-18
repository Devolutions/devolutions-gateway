FROM mcr.microsoft.com/powershell:debian-bullseye-slim
LABEL maintainer "Devolutions Inc."

WORKDIR /opt/devolutions/agent

ENV DAGENT_EXECUTABLE_PATH="/opt/devolutions/agent/devolutions-agent"

COPY devolutions-agent $DAGENT_EXECUTABLE_PATH

RUN apt-get update
RUN apt-get install -y --no-install-recommends ca-certificates curl
RUN rm -rf /var/lib/apt/lists/*

EXPOSE 8080

ENTRYPOINT [ "./devolutions-agent" ]
