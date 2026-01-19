set shell := ["powershell", "-NoProfile", "-Command"]

# Usage:
#   just test video-streamer
#   just test                # defaults to video-streamer
#
# Notes:
# - Requires `DGATEWAY_LIB_XMF_PATH` to point to `xmf.dll` for video streaming tests.
# - Writes logs to `.llm/test-<streamer>.log`.
test streamer="video-streamer":
  @$ErrorActionPreference = 'Continue'; $llm = Join-Path (Get-Location) '.llm'; New-Item -ItemType Directory -Force -Path $llm | Out-Null; $log = Join-Path $llm ('test-' + '{{streamer}}' + '.log'); $env:RUST_LOG = 'video_streamer=info,webm_stream_correctness=info'; $env:RUST_BACKTRACE = '1'; $env:CARGO_TARGET_DIR = Join-Path $env:TEMP ('cargo-target-' + '{{streamer}}' + '-test'); if ('{{streamer}}' -eq 'video-streamer') { cmd /c "cargo test -p video-streamer --test webm_stream_correctness -- --ignored --nocapture 2>&1" | Tee-Object -FilePath $log; if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE } } else { throw ('Unknown streamer: ' + '{{streamer}}' + ' (supported: video-streamer)') }

# Convenience alias (avoids confusion with positional params).
test-streamer:
  @just test video-streamer
