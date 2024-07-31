FROM mcr.microsoft.com/powershell:debian-bullseye-slim
LABEL maintainer "Devolutions Inc."

WORKDIR /opt/devolutions/gateway

ENV DGATEWAY_EXECUTABLE_PATH="/opt/devolutions/gateway/devolutions-gateway"
ENV DGATEWAY_LIB_XMF_PATH="/opt/devolutions/gateway/libxmf.so"
ENV DGATEWAY_WEBAPP_PATH="/opt/devolutions/gateway/webapp"

ADD webapp $DGATEWAY_WEBAPP_PATH
ADD DevolutionsGateway /opt/microsoft/powershell/7/Modules/DevolutionsGateway
COPY devolutions-gateway $DGATEWAY_EXECUTABLE_PATH
COPY "native-libs/libxmf.so" $DGATEWAY_LIB_XMF_PATH

RUN apt-get update
RUN apt-get install -y --no-install-recommends ca-certificates curl
RUN rm -rf /var/lib/apt/lists/*

EXPOSE 8080
EXPOSE 10256

ENTRYPOINT [ "./devolutions-gateway" ]
