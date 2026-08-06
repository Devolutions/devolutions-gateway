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
ARG MULTI_PWSH_X64_SHA256=a0da12c5ac8bdbc72ce307d04e46768f7193830fb83d089473c3460ecd0ccbbb
ARG MULTI_PWSH_ARM64_SHA256=bb232561f8beb2e8f3e7abc607497e15a2205c9865e0ec676496909b3320df3d
ARG MULTI_PWSH_POWERSHELL_VERSION=7.6.4
ARG TARGETARCH

LABEL maintainer="Devolutions Inc."

WORKDIR /opt/devolutions/agent

ENV DAGENT_CONFIG_PATH=/etc/devolutions-agent \
    HOME=/var/lib/devolutions-agent \
    POWERSHELL_TELEMETRY_OPTOUT=1 \
    PSU_AGENT_ID=devolutions-agent-linux \
    PSU_DISPLAY_NAME="Devolutions Agent Linux" \
    PSU_POWERSHELL_EXECUTABLE=/var/lib/devolutions-agent/.pwsh/bin/pwsh

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl libicu76 unzip \
    && case "${TARGETARCH}" in \
        amd64) multi_pwsh_arch=x64; multi_pwsh_sha256="${MULTI_PWSH_X64_SHA256}" ;; \
        arm64) multi_pwsh_arch=arm64; multi_pwsh_sha256="${MULTI_PWSH_ARM64_SHA256}" ;; \
        *) echo "unsupported Docker architecture: ${TARGETARCH}" >&2; exit 1 ;; \
    esac \
    && curl --fail --location --silent --show-error \
        "https://github.com/Devolutions/multi-pwsh/releases/download/${MULTI_PWSH_VERSION}/multi-pwsh-linux-${multi_pwsh_arch}.zip" \
        --output /tmp/multi-pwsh.zip \
    && echo "${multi_pwsh_sha256}  /tmp/multi-pwsh.zip" | sha256sum --check --status \
    && unzip -q /tmp/multi-pwsh.zip -d /tmp/multi-pwsh \
    && install -m 0755 /tmp/multi-pwsh/multi-pwsh /usr/local/bin/multi-pwsh \
    && rm -rf /tmp/multi-pwsh /tmp/multi-pwsh.zip /var/lib/apt/lists/*

RUN useradd --system --create-home --home-dir /var/lib/devolutions-agent --shell /usr/sbin/nologin devolutions-agent \
    && mkdir -p "${DAGENT_CONFIG_PATH}" \
    && runuser -u devolutions-agent -- env HOME="${HOME}" multi-pwsh install "${MULTI_PWSH_POWERSHELL_VERSION}" \
    && runuser -u devolutions-agent -- env HOME="${HOME}" multi-pwsh alias set pwsh "${MULTI_PWSH_POWERSHELL_VERSION}" \
    && runuser -u devolutions-agent -- env HOME="${HOME}" multi-pwsh host pwsh -NoLogo -NoProfile -Command '$PSVersionTable.PSVersion.ToString()' \
    && test -x "${HOME}/.pwsh/bin/pwsh"

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
