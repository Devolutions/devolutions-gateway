# =============================================================================
# Devolutions Gateway — Source build for Coolify
# =============================================================================
# Multi-stage build:
#   1. rust-builder      — compile the gateway binary from source
#   2. official-image    — extract webapp, libxmf, and PowerShell module from official image
#   3. runtime           — assemble the final image
#
# The gateway binary is built from THIS repo's source code, so any Rust changes
# on this branch are included. The webapp, libxmf.so, and PowerShell module
# (with compiled .NET DLLs) come from the official published image.
# =============================================================================

# Global ARG — must be before any FROM to be usable in FROM lines
ARG GATEWAY_VERSION=latest

# ---------------------------------------------------------------------------
# Stage 1: Rust builder
# ---------------------------------------------------------------------------
FROM rust:1.90-bookworm AS rust-builder

WORKDIR /src

# Copy manifests first for better layer caching
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY crates crates
COPY devolutions-gateway devolutions-gateway
COPY devolutions-agent devolutions-agent
COPY devolutions-gateway-agent devolutions-gateway-agent
COPY devolutions-session devolutions-session
COPY jetsocat jetsocat
COPY testsuite testsuite
COPY tools tools
COPY fuzz fuzz

# Build only the gateway binary in release mode
RUN cargo build --release --package devolutions-gateway \
    && cp target/release/devolutions-gateway /usr/local/bin/devolutions-gateway

# ---------------------------------------------------------------------------
# Stage 2: Extract webapp + libxmf from the official image
# ---------------------------------------------------------------------------
FROM devolutions/devolutions-gateway:${GATEWAY_VERSION} AS official-image

# ---------------------------------------------------------------------------
# Stage 3: Runtime
# ---------------------------------------------------------------------------
FROM debian:bookworm-slim

LABEL maintainer="Devolutions Inc."
LABEL description="Devolutions Gateway — built from source with web UI"

# Install PowerShell and runtime dependencies
RUN apt-get update \
    && apt-get install -y --no-install-recommends wget ca-certificates openssl curl \
    && ARCH=$(dpkg --print-architecture) \
    && if [ "$ARCH" = "arm64" ]; then \
        PWSH_VERSION=7.4.6 \
        && wget -q "https://github.com/PowerShell/PowerShell/releases/download/v${PWSH_VERSION}/powershell-${PWSH_VERSION}-linux-arm64.tar.gz" \
        && mkdir -p /opt/microsoft/powershell/7 \
        && tar -xzf "powershell-${PWSH_VERSION}-linux-arm64.tar.gz" -C /opt/microsoft/powershell/7 \
        && chmod +x /opt/microsoft/powershell/7/pwsh \
        && ln -s /opt/microsoft/powershell/7/pwsh /usr/bin/pwsh \
        && rm "powershell-${PWSH_VERSION}-linux-arm64.tar.gz"; \
    else \
        wget -q https://packages.microsoft.com/config/debian/12/packages-microsoft-prod.deb -O packages-microsoft-prod.deb \
        && dpkg -i packages-microsoft-prod.deb \
        && rm packages-microsoft-prod.deb \
        && apt-get update \
        && apt-get install -y --no-install-recommends powershell; \
    fi \
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

# Gateway binary — built from THIS repo's source code
COPY --from=rust-builder /usr/local/bin/devolutions-gateway $DGATEWAY_EXECUTABLE_PATH

# Webapp + libxmf — extracted from official image
COPY --from=official-image /opt/devolutions/gateway/webapp $DGATEWAY_WEBAPP_PATH
COPY --from=official-image /opt/devolutions/gateway/libxmf.so $DGATEWAY_LIB_XMF_PATH

# PowerShell module — from official image (includes pre-compiled .NET DLLs)
COPY --from=official-image /opt/microsoft/powershell/7/Modules/DevolutionsGateway /opt/microsoft/powershell/7/Modules/DevolutionsGateway

# Entrypoint script from this repo's source
COPY package/Linux/entrypoint.ps1 /usr/local/bin/entrypoint.ps1
RUN chmod +x /usr/local/bin/entrypoint.ps1

EXPOSE 7171
EXPOSE 8181
EXPOSE 51820/udp

HEALTHCHECK --interval=30s --timeout=10s --retries=5 --start-period=15s \
    CMD curl -sf http://localhost:7171/jet/health || exit 1

ENTRYPOINT ["pwsh", "-File", "/usr/local/bin/entrypoint.ps1"]
