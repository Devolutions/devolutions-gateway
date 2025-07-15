FROM debian:bookworm-slim
LABEL maintainer="Devolutions Inc."

RUN apt-get update \
    && apt-get install -y --no-install-recommends wget ca-certificates \
    && wget -q https://packages.microsoft.com/config/debian/12/packages-microsoft-prod.deb -O packages-microsoft-prod.deb \
    && dpkg -i packages-microsoft-prod.deb \
    && rm packages-microsoft-prod.deb \
    && apt-get update \
    && apt-get install -y --no-install-recommends \
        powershell openssl \
    && rm -rf /var/lib/apt/lists/*

ENV XDG_CACHE_HOME="/tmp/.cache"
ENV XDG_DATA_HOME="/tmp/.local/share"
ENV POWERSHELL_TELEMETRY_OPTOUT="1"

ENV DGATEWAY_CONFIG_PATH="/tmp/devolutions-gateway"
RUN mkdir -p "$DGATEWAY_CONFIG_PATH"

WORKDIR /opt/devolutions/gateway

ENV DGATEWAY_EXECUTABLE_PATH="/opt/devolutions/gateway/devolutions-gateway"
ENV DGATEWAY_LIB_XMF_PATH="/opt/devolutions/gateway/libxmf.so"
ENV DGATEWAY_WEBAPP_PATH="/opt/devolutions/gateway/webapp"

ADD webapp $DGATEWAY_WEBAPP_PATH
ADD DevolutionsGateway /opt/microsoft/powershell/7/Modules/DevolutionsGateway
COPY devolutions-gateway $DGATEWAY_EXECUTABLE_PATH
COPY libxmf.so $DGATEWAY_LIB_XMF_PATH

RUN apt-get update
RUN apt-get install -y --no-install-recommends ca-certificates curl
RUN rm -rf /var/lib/apt/lists/*

EXPOSE 7171
EXPOSE 8181

COPY entrypoint.ps1 /usr/local/bin/entrypoint.ps1
RUN chmod +x /usr/local/bin/entrypoint.ps1
ENTRYPOINT ["pwsh", "-File", "/usr/local/bin/entrypoint.ps1"]
