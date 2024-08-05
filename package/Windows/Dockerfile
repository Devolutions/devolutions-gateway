ARG FROM_IMAGE=mcr.microsoft.com/powershell:windowsservercore-ltsc2022
FROM ${FROM_IMAGE}

LABEL maintainer "Devolutions Inc."

WORKDIR "C:\\Devolutions\Gateway"

ENV DGATEWAY_EXECUTABLE_PATH="C:\\Devolutions\Gateway\DevolutionsGateway.exe"
ENV DGATEWAY_LIB_XMF_PATH="C:\\Devolutions\Gateway\xmf.dll"
ENV DGATEWAY_WEBAPP_PATH="C:\\Devolutions\Gateway\webapp"

ADD webapp $DGATEWAY_WEBAPP_PATH
ADD DevolutionsGateway C:\\Devolutions\\Gateway\\PowerShell\\Modules\\DevolutionsGateway
COPY DevolutionsGateway.exe $DGATEWAY_EXECUTABLE_PATH
COPY xmf.dll $DGATEWAY_LIB_XMF_PATH

ENV PSModulePath="${PSModulePath}C:\\Devolutions\\Gateway\\PowerShell\\Modules;"

EXPOSE 8080
EXPOSE 10256

ENTRYPOINT ["C:\\Devolutions\\Gateway\\DevolutionsGateway.exe"]
