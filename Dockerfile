# Devolutions Gateway — Coolify-ready container
#
# This Dockerfile extends the official image. Use it when you need to:
#   - Add custom certificates at build time
#   - Bundle additional tools or scripts
#   - Pin a specific version for reproducibility
#
# For most deployments, the docker-compose.yml uses the official image directly
# and this file is NOT required. To use this Dockerfile instead, change
# docker-compose.yml to:
#
#   services:
#     gateway:
#       build: .
#       # (remove the "image:" line)
#

ARG GATEWAY_VERSION=latest
FROM devolutions/devolutions-gateway:${GATEWAY_VERSION}

LABEL maintainer="Devolutions Inc."
LABEL description="Devolutions Gateway — standalone mode with web UI"

# Health check endpoint
HEALTHCHECK --interval=30s --timeout=10s --retries=5 --start-period=15s \
  CMD curl -sf http://localhost:7171/jet/health || exit 1
