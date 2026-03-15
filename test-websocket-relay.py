import argparse
import asyncio
import base64
import json
import sys
import urllib.parse

import websockets


def decode_session_id(token: str) -> str:
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("token is not a compact JWT")

    payload = parts[1]
    payload += "=" * ((4 - len(payload) % 4) % 4)
    claims = json.loads(base64.urlsafe_b64decode(payload.encode("ascii")))
    return claims["jet_aid"]


async def run_client(args: argparse.Namespace) -> int:
    session_id = args.session_id or decode_session_id(args.token)
    token = urllib.parse.quote(args.token, safe="")
    url = f"{args.gateway_url.rstrip('/')}/jet/fwd/tcp/{session_id}?token={token}"
    request_bytes = args.request.encode("ascii")
    expected_marker = args.expected_marker.encode("utf-8")

    print(f"Connecting to {url}", file=sys.stderr)

    async with websockets.connect(url, max_size=None) as websocket:
        await websocket.send(request_bytes)

        response_chunks: list[bytes] = []

        try:
            while True:
                message = await asyncio.wait_for(websocket.recv(), timeout=args.idle_timeout)
                if isinstance(message, str):
                    response_chunks.append(message.encode("utf-8"))
                else:
                    response_chunks.append(message)
                if expected_marker in b"".join(response_chunks):
                    break
        except TimeoutError:
            if not response_chunks:
                raise
        except websockets.exceptions.ConnectionClosed:
            pass

    response = b"".join(response_chunks)
    sys.stdout.buffer.write(response)
    sys.stdout.buffer.flush()

    if expected_marker not in response:
        print("\nExpected HTTP payload marker missing from response.", file=sys.stderr)
        return 1

    return 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Exercise Gateway WebSocket TCP forwarding over WireGuard.")
    parser.add_argument("--gateway-url", default="ws://127.0.0.1:7171")
    parser.add_argument("--session-id")
    parser.add_argument("--token", required=True)
    parser.add_argument(
        "--request",
        default="GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    )
    parser.add_argument("--expected-marker", default="Hello from Agent Container!")
    parser.add_argument("--idle-timeout", type=float, default=5.0)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    return asyncio.run(run_client(args))


if __name__ == "__main__":
    raise SystemExit(main())
