# IronVNC H.264 gateway-webapp demo

Runs the Devolutions Gateway webapp (`gateway-ui`) against the IronVNC web client built
from the `claude/h264-native-webcodec-arch-rdlycy` branch, so the browser negotiates and
decodes **H.264 (OpenH264, encoding 50)** over VNC through the gateway.

## Why the custom tooling

`gateway-ui`'s Angular build in this checkout misclassifies the application **entry** as a
lazy chunk, so neither `ng serve` nor `ng build` injects `main.js`/`polyfills.js`/`styles.css`
into `index.html` — the app renders a blank page. We work around it instead of fighting it:

- **`inject-entry.cjs`** — run after every `ng build`; patches the built
  `webapp/dist/gateway-ui/index.html` with the missing `<script>`/`<link>` tags **and** the
  H.264 → WebCodecs presenter bridge (idempotent).
- **`serve-demo.cjs`** — serves that patched `dist/gateway-ui` statically and proxies
  `/jet/*` (incl. the `/jet/fwd/tcp` WebSocket tunnel) to the real gateway on `:7272`.

This sidesteps the broken Angular dev/build injection entirely.

## Prerequisites (already running on this machine)

- Devolutions Gateway on `:7272` (auth `None`), token server on `:8080`.
- For a local smoke test: the OpenH264 mock server
  `IronVNC/web-client/webcodecs-e2e/mock-h264-server.cjs` on `127.0.0.1:5999`.

## Rebuild + run

```powershell
# one-shot rebuild (wasm -> tarball -> install -> ng build -> inject)
pwsh ./rebuild-demo.ps1            # add -SkipWasm to reuse the existing wasm tarball

# serve it (static + gateway proxy) on http://localhost:4300/jet/webapp/client/
node ./serve-demo.cjs
```

Then open `http://localhost:4300/jet/webapp/client/`, New Session → Protocol **VNC** →
hostname of an H.264-capable VNC server (e.g. TigerVNC built with H.264) → Connect.

## What "working" looks like

- Browser console: `Probed WebCodecs H.264 decode support h264_supported=true`
- Browser console: `Advertise encodings encodings=[... OPEN_H264{0050} ...]`
- Server receives `SetEncodings` including `50` and starts sending H.264.
- Console: `[h264-presenter] attached to render canvas` and the video renders.

Smoke test against the mock:

```sh
cd ../IronVNC/web-client/webcodecs-e2e
node mock-h264-server.cjs &
WEBAPP_URL=http://localhost:4300/jet/webapp/client/ node verify-motion.cjs   # => ANIMATING
```

## Notes

- OpenH264 is advertised **only when the browser's WebCodecs can decode H.264** (probed via
  `VideoDecoder.isConfigSupported('avc1.42E01E')` in the wasm), so we never ask a server for
  a stream we can't display.
- Only the **OpenH264 (50)** encoding is wired end-to-end on the branch. Mac ARD's H.264
  (`ARD_AVC`, 1010) is not yet framed, so use a **Linux TigerVNC + H.264** server to test.
