ARG FROM_IMAGE=mcr.microsoft.com/powershell:windowsservercore-ltsc2022
FROM ${FROM_IMAGE}

LABEL maintainer "Devolutions Inc."

ADD webapp "C:\\Devolutions\Gateway\webapp"

WORKDIR "C:\\Devolutions\Gateway"

COPY DevolutionsGateway.exe .

EXPOSE 8080
EXPOSE 10256

ENTRYPOINT ["c:\\Devolutions\\Gateway\\DevolutionsGateway.exe"]
