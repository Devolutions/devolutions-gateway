FROM debian:bookworm-slim
LABEL maintainer="Devolutions Inc."

RUN apt-get update \
    && apt-get install -y --no-install-recommends wget ca-certificates \
    && wget -q https://packages.microsoft.com/config/debian/12/packages-microsoft-prod.deb -O packages-microsoft-prod.deb \
    && dpkg -i packages-microsoft-prod.deb \
    && rm packages-microsoft-prod.deb \
    && apt-get update \
    && apt-get install -y --no-install-recommends \
        powershell \
    && rm -rf /var/lib/apt/lists/*

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

EXPOSE 8080
EXPOSE 10256

ENTRYPOINT [ "./devolutions-gateway" ]
