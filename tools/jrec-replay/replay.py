#!/usr/bin/env python3

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import socket
import ssl
import struct
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit


WEBSOCKET_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


@dataclass(frozen=True)
class ConnectionCapture:
    path: Path
    opened_at_run_us: int
    file_type: str
    events: tuple[dict[str, object], ...]


class WebSocketClient:
    def __init__(self, url: str, connect_timeout: float) -> None:
        self._socket = self._connect(url, connect_timeout)
        self._send_lock = threading.Lock()
        self._closed = threading.Event()
        self._close_sent = False
        self._receive_error: BaseException | None = None
        self._receive_buffer = bytearray()
        self._receive_thread = threading.Thread(target=self._receive_loop, name="jrec-replay-receive", daemon=True)
        self._receive_thread.start()

    @property
    def closed(self) -> bool:
        return self._closed.is_set()

    def send_message(self, message_type: str, payload: bytes) -> None:
        if self.closed:
            if self._receive_error is not None:
                raise ConnectionError("gateway WebSocket closed") from self._receive_error
            raise ConnectionError("gateway WebSocket closed")

        opcode = {
            "text": 0x1,
            "binary": 0x2,
            "ping": 0x9,
        }.get(message_type)
        if opcode is None:
            if message_type == "pong":
                return
            raise ValueError(f"unsupported captured message type: {message_type}")
        self._send_frame(opcode, payload)

    def close(self, code: int | None = 1000, reason: str = "") -> None:
        if not self._close_sent and not self.closed:
            payload = b"" if code is None else struct.pack("!H", code) + reason.encode("utf-8")
            try:
                self._send_frame(0x8, payload)
                self._close_sent = True
            except OSError:
                pass

        self._closed.wait(timeout=1.0)
        try:
            self._socket.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        self._socket.close()
        self._closed.set()
        if self._receive_thread.is_alive():
            self._receive_thread.join(timeout=1.0)

    def _connect(self, url: str, connect_timeout: float) -> socket.socket:
        parts = urlsplit(url)
        if parts.scheme not in {"ws", "wss"}:
            raise ValueError("WebSocket URL must use ws:// or wss://")
        if parts.hostname is None:
            raise ValueError("WebSocket URL is missing a host")

        secure = parts.scheme == "wss"
        port = parts.port or (443 if secure else 80)
        stream = socket.create_connection((parts.hostname, port), timeout=connect_timeout)
        if secure:
            stream = ssl.create_default_context().wrap_socket(stream, server_hostname=parts.hostname)
        stream.settimeout(connect_timeout)

        key = base64.b64encode(os.urandom(16)).decode("ascii")
        resource = parts.path or "/"
        if parts.query:
            resource = f"{resource}?{parts.query}"
        default_port = 443 if secure else 80
        host = parts.hostname if port == default_port else f"{parts.hostname}:{port}"
        request = (
            f"GET {resource} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {key}\r\n"
            "Sec-WebSocket-Version: 13\r\n"
            "\r\n"
        )
        stream.sendall(request.encode("ascii"))

        response = bytearray()
        while b"\r\n\r\n" not in response:
            chunk = stream.recv(4096)
            if not chunk:
                raise ConnectionError("gateway closed during the WebSocket handshake")
            response.extend(chunk)
            if len(response) > 64 * 1024:
                raise ConnectionError("WebSocket handshake response is too large")

        header_bytes, remaining = response.split(b"\r\n\r\n", 1)
        lines = header_bytes.decode("iso-8859-1").split("\r\n")
        if len(lines) == 0 or " 101 " not in f" {lines[0]} ":
            raise ConnectionError(f"WebSocket upgrade failed: {lines[0] if lines else 'empty response'}")
        headers = {}
        for line in lines[1:]:
            name, separator, value = line.partition(":")
            if separator:
                headers[name.strip().lower()] = value.strip()
        expected_accept = base64.b64encode(hashlib.sha1((key + WEBSOCKET_GUID).encode("ascii")).digest()).decode("ascii")
        if headers.get("sec-websocket-accept") != expected_accept:
            raise ConnectionError("gateway returned an invalid WebSocket accept value")

        stream.settimeout(None)
        self._initial_receive_buffer = bytes(remaining)
        return stream

    def _send_frame(self, opcode: int, payload: bytes) -> None:
        mask = os.urandom(4)
        length = len(payload)
        header = bytearray([0x80 | opcode])
        if length < 126:
            header.append(0x80 | length)
        elif length <= 0xFFFF:
            header.append(0x80 | 126)
            header.extend(struct.pack("!H", length))
        else:
            header.append(0x80 | 127)
            header.extend(struct.pack("!Q", length))
        header.extend(mask)
        masked_payload = bytes(value ^ mask[index % 4] for index, value in enumerate(payload))
        with self._send_lock:
            self._socket.sendall(header)
            self._socket.sendall(masked_payload)

    def _receive_loop(self) -> None:
        self._receive_buffer.extend(self._initial_receive_buffer)
        try:
            while not self.closed:
                opcode, payload = self._receive_frame()
                if opcode == 0x8:
                    if not self._close_sent:
                        self._send_frame(0x8, payload)
                        self._close_sent = True
                    break
                if opcode == 0x9:
                    self._send_frame(0xA, payload)
        except (ConnectionError, OSError) as error:
            if not self._close_sent:
                self._receive_error = error
        finally:
            self._closed.set()

    def _receive_frame(self) -> tuple[int, bytes]:
        header = self._receive_exact(2)
        opcode = header[0] & 0x0F
        masked = header[1] & 0x80 != 0
        length = header[1] & 0x7F
        if length == 126:
            length = struct.unpack("!H", self._receive_exact(2))[0]
        elif length == 127:
            length = struct.unpack("!Q", self._receive_exact(8))[0]
        mask = self._receive_exact(4) if masked else None
        payload = self._receive_exact(length)
        if mask is not None:
            payload = bytes(value ^ mask[index % 4] for index, value in enumerate(payload))
        return opcode, payload

    def _receive_exact(self, length: int) -> bytes:
        while len(self._receive_buffer) < length:
            chunk = self._socket.recv(max(4096, length - len(self._receive_buffer)))
            if not chunk:
                raise ConnectionError("gateway WebSocket closed without a close frame")
            self._receive_buffer.extend(chunk)
        result = bytes(self._receive_buffer[:length])
        del self._receive_buffer[:length]
        return result


def load_capture(session_path: Path) -> list[ConnectionCapture]:
    connections = []
    for connection_path in session_path.glob("connection-*"):
        if not connection_path.is_dir():
            continue
        metadata = json.loads((connection_path / "metadata.json").read_text(encoding="utf-8"))
        if metadata.get("format_version") != 1:
            raise ValueError(f"unsupported capture format in {connection_path}")
        events = tuple(
            json.loads(line)
            for line in (connection_path / "events.jsonl").read_text(encoding="utf-8").splitlines()
            if line
        )
        finished = tuple(event for event in events if event.get("event") == "finished")
        if len(finished) != 1:
            raise ValueError(f"capture must contain one finished event in {connection_path}")
        if not bool(finished[0].get("complete", True)):
            raise ValueError(f"capture is incomplete in {connection_path}")
        if finished[0].get("outcome") != "done":
            raise ValueError(f"capture outcome is {finished[0].get('outcome')!r} in {connection_path}")
        connections.append(
            ConnectionCapture(
                path=connection_path,
                opened_at_run_us=int(metadata["opened_at_run_us"]),
                file_type=str(metadata["file_type"]),
                events=events,
            )
        )
    if not connections:
        raise ValueError(f"no connection captures found in {session_path}")
    connections.sort(key=lambda connection: connection.opened_at_run_us)
    return connections


def url_for_connection(url: str, file_type: str) -> str:
    parts = urlsplit(url)
    query = parse_qsl(parts.query, keep_blank_values=True)
    if not any(name == "fileType" for name, _ in query):
        query.append(("fileType", file_type))
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(query), parts.fragment))


def sleep_until(deadline: float) -> None:
    remaining = deadline - time.monotonic()
    if remaining > 0:
        time.sleep(remaining)


def replay_connection(connection: ConnectionCapture, url: str, connect_timeout: float) -> tuple[int, int]:
    client = WebSocketClient(url_for_connection(url, connection.file_type), connect_timeout)
    started_at = time.monotonic()
    sent_messages = 0
    sent_bytes = 0
    close_sent = False
    payload_path = connection.path / "payload.bin"

    try:
        with payload_path.open("rb") as payload_file:
            for event in connection.events:
                event_type = event["event"]
                sleep_until(started_at + int(event["time_us"]) / 1_000_000)
                if event_type == "message":
                    data = read_payload(payload_file, int(event["offset"]), int(event["length"]))
                    client.send_message(str(event["message_type"]), data)
                    sent_messages += 1
                    sent_bytes += len(data)
                elif event_type == "close":
                    code = event.get("code")
                    client.close(None if code is None else int(code), str(event.get("reason") or ""))
                    close_sent = True
                elif event_type == "finished":
                    break
                else:
                    raise ValueError(f"unsupported capture event: {event_type}")
    finally:
        if not close_sent:
            client.close()

    return sent_messages, sent_bytes


def read_payload(payload_file: BinaryIO, offset: int, length: int) -> bytes:
    payload_file.seek(offset)
    data = payload_file.read(length)
    if len(data) != length:
        raise ValueError(f"capture payload ended at {len(data)} bytes; expected {length}")
    return data


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Replay a Gateway JREC push capture with its original connection timing.")
    parser.add_argument("capture", type=Path, help="Session capture directory containing connection-* directories.")
    parser.add_argument("--url", required=True, help="Fresh ws:// or wss:// JREC push URL, including its token.")
    parser.add_argument("--connect-timeout", type=float, default=10.0, help="WebSocket connection timeout in seconds.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    connections = load_capture(args.capture.resolve())
    first_open_us = connections[0].opened_at_run_us
    replay_started_at = time.monotonic()
    total_messages = 0
    total_bytes = 0

    for index, connection in enumerate(connections, start=1):
        open_delay = (connection.opened_at_run_us - first_open_us) / 1_000_000
        sleep_until(replay_started_at + open_delay)
        print(f"[{index}/{len(connections)}] replay {connection.path.name}", flush=True)
        messages, payload_bytes = replay_connection(connection, args.url, args.connect_timeout)
        total_messages += messages
        total_bytes += payload_bytes

    print(f"replayed {len(connections)} connections, {total_messages} messages, {total_bytes} bytes")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (ConnectionError, OSError, ValueError, json.JSONDecodeError) as error:
        print(f"error: {error}", file=sys.stderr)
        sys.exit(1)
