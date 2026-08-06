ARG BUILD_TARGET=artifact

FROM rust:1.90-bookworm AS build

WORKDIR /workspace

ENV CARGO_NET_GIT_FETCH_WITH_CLI=true

RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential clang cmake git libclang-dev pkg-config \
    && rm -rf /var/lib/apt/lists/*

COPY . .

RUN rm -f rust-toolchain.toml \
    && cargo build --package devolutions-agent --release

FROM debian:trixie-slim AS runtime-base

ARG MULTI_PWSH_VERSION=v0.17.0
ARG TARGETARCH

LABEL maintainer="Devolutions Inc."

WORKDIR /opt/devolutions/agent

ENV DAGENT_CONFIG_PATH=/etc/devolutions-agent \
    POWERSHELL_TELEMETRY_OPTOUT=1 \
    PSU_AGENT_ID=devolutions-agent-linux \
    PSU_DISPLAY_NAME="Devolutions Agent Linux" \
    PSU_POWERSHELL_EXECUTABLE=/usr/local/bin/pwsh

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl libicu76 unzip \
    && case "${TARGETARCH}" in \
        amd64) multi_pwsh_arch=x64 ;; \
        arm64) multi_pwsh_arch=arm64 ;; \
        *) echo "unsupported Docker architecture: ${TARGETARCH}" >&2; exit 1 ;; \
    esac \
    && curl --fail --location --silent --show-error \
        "https://github.com/Devolutions/multi-pwsh/releases/download/${MULTI_PWSH_VERSION}/multi-pwsh-linux-${multi_pwsh_arch}.zip" \
        --output /tmp/multi-pwsh.zip \
    && unzip -q /tmp/multi-pwsh.zip -d /tmp/multi-pwsh \
    && install -m 0755 /tmp/multi-pwsh/multi-pwsh /usr/local/bin/multi-pwsh \
    && multi-pwsh install stable --scope machine \
    && test -x /usr/local/bin/pwsh \
    && rm -rf /tmp/multi-pwsh /tmp/multi-pwsh.zip /var/lib/apt/lists/*

RUN useradd --system --create-home --home-dir /var/lib/devolutions-agent --shell /usr/sbin/nologin devolutions-agent \
    && mkdir -p "${DAGENT_CONFIG_PATH}"

FROM runtime-base AS runtime-artifact

COPY devolutions-agent /opt/devolutions/agent/devolutions-agent
COPY devolutions-agent-entrypoint.sh /usr/local/bin/devolutions-agent-entrypoint.sh

FROM runtime-base AS runtime-local

COPY --from=build /workspace/target/release/devolutions-agent /opt/devolutions/agent/devolutions-agent
COPY devolutions-agent/docker/devolutions-agent-entrypoint.sh /usr/local/bin/devolutions-agent-entrypoint.sh

FROM runtime-${BUILD_TARGET}

RUN chown -R devolutions-agent:devolutions-agent "${DAGENT_CONFIG_PATH}" /opt/devolutions/agent \
    && chmod +x /opt/devolutions/agent/devolutions-agent /usr/local/bin/devolutions-agent-entrypoint.sh

USER devolutions-agent

ENTRYPOINT ["/usr/local/bin/devolutions-agent-entrypoint.sh"]
