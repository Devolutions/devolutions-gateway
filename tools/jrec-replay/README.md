# JREC push capture and replay

This tool captures real RDM and DVLS recording uploads once, then replays them against a local Gateway without starting RDM or DVLS.

The Gateway recorder is passive.
It preserves payload messages, close frames, connection boundaries, and timing without parsing or changing WebM data.
WebSocket keep-alive responses follow the new connection instead of replaying control frames from the old connection.

## Capture

Set an absolute capture directory before starting Gateway:

```powershell
$env:DGATEWAY_JREC_CAPTURE_DIR = 'D:\gateway-jrec-captures'
```

Run a recording through real RDM or DVLS.
Gateway creates this structure:

```text
D:\gateway-jrec-captures\
└── run-<ulid>\
    └── <recording-id>\
        ├── connection-<ulid>\
        │   ├── metadata.json
        │   ├── events.jsonl
        │   └── payload.bin
        └── connection-<ulid>\
```

RDM resolution changes appear as several connection directories.
A DVLS browser recording normally appears as one connection directory, even when its WebM changes resolution.

Unset the variable to disable capture:

```powershell
Remove-Item Env:DGATEWAY_JREC_CAPTURE_DIR
```

## Replay

Create a fresh JREC push URL for the target local Gateway.
The recording ID in the URL and token may differ from the captured ID.

Run the replayer with Python 3:

```powershell
python 'D:\devolutions-gateway\tools\jrec-replay\replay.py' `
  'D:\gateway-jrec-captures\run-<ulid>\<recording-id>' `
  --url 'ws://localhost:7171/jet/jrec/push/<new-recording-id>?token=<fresh-push-token>'
```

The replayer uses only the Python standard library.
It opens each captured WebSocket in order, sends each message at its recorded offset, and preserves gaps between connections.
It rejects incomplete captures and captures whose original Gateway upload did not finish successfully.

## Data handling

Captures contain screen pixels and may contain private information.
Use controlled lab sessions.
Keep raw captures outside this repository unless every frame has been reviewed and approved for source control.
