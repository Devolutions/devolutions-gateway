# web-recorder-tester

A live, end-to-end harness for [`@devolutions/web-recorder`](../../packages/web-recorder). It animates a
rotating Milky Way (additive particle glow + drifting starfield) with a live wall-clock and elapsed-record
readout in the top-right corner, captures that canvas with `WebMRecorder`, and pushes the WebM stream to a
real Gateway through the `/jet/jrec/push` endpoint.

It is the capture-side counterpart to `recording-player-tester` (playback side) and uses the same dev
services.

## Prerequisites

1. **Gateway** running locally (default `localhost:7171`).
2. **tokengen** in server mode on `:8080` (mints the push token):

   ```
   cargo run -p tokengen -- --provisioner-key <key.pem> server
   ```

   (Same token server the `recording-player-tester` relies on.)

## Run

```
pnpm --filter web-recorder-tester dev
```

Open the printed URL, confirm the Gateway host, and click **Start recording**. The page:

1. generates a random session id,
2. `POST /jrec { jet_rop: 'push', jet_aid: <id> }` to tokengen for a push token,
3. opens `ws://<gateway>/jet/jrec/push/<id>?token=…` (WebMRecorder appends `&fileType=webm`),
4. streams the animated canvas as WebM.

Click **Stop**, copy the shown **Recording id**, and play it back in `recording-player-tester` using that
session id.
