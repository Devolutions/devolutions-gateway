ARG FROM_IMAGE=mcr.microsoft.com/windows/servercore:ltsc2019
FROM ${FROM_IMAGE}

LABEL maintainer "Devolutions Inc."

WORKDIR "C:\\wayk"

COPY DevolutionsGateway.exe .

EXPOSE 8080
EXPOSE 10256

ENTRYPOINT ["c:\\wayk\\DevolutionsGateway.exe"]
