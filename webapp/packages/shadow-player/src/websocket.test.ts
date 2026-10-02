// @vitest-environment jsdom

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { ServerWebSocket } from './websocket';

interface Deferred<T> {
  promise: Promise<T>;
  resolve: (value: T | PromiseLike<T>) => void;
}

function deferred<T>(): Deferred<T> {
  let resolve!: Deferred<T>['resolve'];
  const promise = new Promise<T>((promiseResolve) => {
    resolve = promiseResolve;
  });
  return { promise, resolve };
}

function encodedMessage(type: number, payload = ''): ArrayBuffer {
  const encodedPayload = new TextEncoder().encode(payload);
  const message = new Uint8Array(1 + encodedPayload.length);
  message[0] = type;
  message.set(encodedPayload, 1);
  return message.buffer;
}

class FakeWebSocket {
  static readonly OPEN = 1;
  static latest: FakeWebSocket | null = null;
  static instances: FakeWebSocket[] = [];

  binaryType: BinaryType = 'blob';
  readyState = FakeWebSocket.OPEN;
  protocol = '';
  onopen: ((event: Event) => void) | null = null;
  onmessage: ((event: MessageEvent) => void) | null = null;
  onclose: ((event: CloseEvent) => void) | null = null;
  onerror: ((event: Event) => void) | null = null;

  constructor(
    readonly url: string,
    readonly protocols?: string | string[],
  ) {
    FakeWebSocket.latest = this;
    FakeWebSocket.instances.push(this);
  }

  send(): void {}

  close(): void {}

  emitOpen(): void {
    this.onopen?.(new Event('open'));
  }

  emitMessage(data: ArrayBuffer): void {
    this.onmessage?.(new MessageEvent('message', { data }));
  }

  emitClose(): void {
    this.onclose?.(new CloseEvent('close', { code: 1006 }));
  }

  emitError(): void {
    this.onerror?.(new Event('error'));
  }

  /** A failed handshake, as browsers report it: error, then close with 1006. */
  emitHandshakeFailure(): void {
    this.emitError();
    this.emitClose();
  }
}

/** Lets every queued event callback run: a macrotask turn drains all pending microtasks first. */
function settle(): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, 0));
}

describe('ServerWebSocket', () => {
  beforeEach(() => {
    vi.stubGlobal('WebSocket', FakeWebSocket);
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    FakeWebSocket.latest = null;
    FakeWebSocket.instances = [];
  });

  it('falls back to shadow protocol v1 when the v2 handshake fails', async () => {
    const websocket = new ServerWebSocket('ws://example.test');
    const onopen = vi.fn();
    const onerror = vi.fn();
    const onclose = vi.fn();
    websocket.onopen(onopen);
    websocket.onerror(onerror);
    websocket.onclose(onclose);

    FakeWebSocket.instances[0]?.emitHandshakeFailure();
    await settle();

    expect(FakeWebSocket.instances).toHaveLength(2);
    expect(FakeWebSocket.instances[1]?.url).toBe('ws://example.test');
    expect(FakeWebSocket.instances[1]?.protocols).toEqual([]);
    expect(onerror).not.toHaveBeenCalled();
    expect(onclose).not.toHaveBeenCalled();

    FakeWebSocket.instances[1]?.emitOpen();
    expect(onopen).toHaveBeenCalledTimes(1);
    expect(websocket.shadowProtocolVersion()).toBe('v1');
  });

  it('reports the failure when the v1 fallback also fails', async () => {
    const websocket = new ServerWebSocket('ws://example.test');
    const onerror = vi.fn();
    const onclose = vi.fn();
    websocket.onerror(onerror);
    websocket.onclose(onclose);

    FakeWebSocket.instances[0]?.emitHandshakeFailure();
    FakeWebSocket.instances[1]?.emitHandshakeFailure();
    await settle();

    expect(FakeWebSocket.instances).toHaveLength(2);
    expect(onerror).toHaveBeenCalledTimes(1);
    expect(onclose).toHaveBeenCalledTimes(1);
  });

  it('does not reconnect when an opened socket closes', async () => {
    const websocket = new ServerWebSocket('ws://example.test');
    const onclose = vi.fn();
    websocket.onclose(onclose);

    FakeWebSocket.instances[0]?.emitOpen();
    FakeWebSocket.instances[0]?.emitClose();
    await settle();

    expect(FakeWebSocket.instances).toHaveLength(1);
    expect(onclose).toHaveBeenCalledTimes(1);
  });

  it('does not reconnect when the caller closes before the socket opens', async () => {
    const websocket = new ServerWebSocket('ws://example.test');
    const onclose = vi.fn();
    websocket.onclose(onclose);

    websocket.close(1000, 'replaced');
    FakeWebSocket.instances[0]?.emitClose();
    await settle();

    expect(FakeWebSocket.instances).toHaveLength(1);
    expect(onclose).toHaveBeenCalledTimes(1);
  });

  it('offers shadow protocol v2 during the handshake', () => {
    new ServerWebSocket('ws://example.test');

    expect(FakeWebSocket.latest?.protocols).toEqual(['jrec-shadow.v2']);
  });

  it('reports the shadow protocol version the Gateway selected', () => {
    const websocket = new ServerWebSocket('ws://example.test');
    const socket = FakeWebSocket.latest;
    expect(socket).not.toBeNull();

    expect(websocket.shadowProtocolVersion()).toBe('v1');
    if (socket) {
      socket.protocol = 'jrec-shadow.v2';
    }
    expect(websocket.shadowProtocolVersion()).toBe('v2');
  });

  it('accepts segment-started on a v1 connection', async () => {
    const websocket = new ServerWebSocket('ws://example.test');
    const received = deferred<string>();
    const onFailure = vi.fn();
    websocket.onmessage((message) => received.resolve(message.type), onFailure);

    FakeWebSocket.latest?.emitOpen();
    FakeWebSocket.latest?.emitMessage(encodedMessage(4, '{"codec":"vp8"}'));

    expect(await received.promise).toBe('segment-started');
    expect(websocket.shadowProtocolVersion()).toBe('v1');
    expect(onFailure).not.toHaveBeenCalled();
  });

  it('serializes messages and dispatches close after pending message work', async () => {
    const websocket = new ServerWebSocket('ws://example.test');
    const socket = FakeWebSocket.latest;
    expect(socket).not.toBeNull();

    const firstStarted = deferred<void>();
    const releaseFirst = deferred<void>();
    const secondStarted = deferred<void>();
    const closed = deferred<void>();
    const calls: string[] = [];

    websocket.onmessage(async (message) => {
      calls.push(message.type);
      if (message.type === 'metadata') {
        firstStarted.resolve();
        await releaseFirst.promise;
      } else {
        secondStarted.resolve();
      }
    }, vi.fn());
    websocket.onclose(() => closed.resolve());

    socket?.emitOpen();
    socket?.emitMessage(encodedMessage(1, '{"codec":"vp8"}'));
    socket?.emitMessage(encodedMessage(0, 'chunk'));
    socket?.emitClose();

    await firstStarted.promise;
    await Promise.resolve();
    expect(calls).toEqual(['metadata']);

    let closeDispatched = false;
    void closed.promise.then(() => {
      closeDispatched = true;
    });
    await Promise.resolve();
    expect(closeDispatched).toBe(false);

    releaseFirst.resolve();
    await secondStarted.promise;
    await closed.promise;
    expect(calls).toEqual(['metadata', 'chunk']);
  });

  it('serializes an error after a queued stream end', async () => {
    const websocket = new ServerWebSocket('ws://example.test');
    const socket = FakeWebSocket.latest;
    expect(socket).not.toBeNull();

    const endStarted = deferred<void>();
    const releaseEnd = deferred<void>();
    const errorDispatched = deferred<void>();

    websocket.onmessage(async (message) => {
      expect(message).toEqual({ type: 'stream-ended' });
      endStarted.resolve();
      await releaseEnd.promise;
    }, vi.fn());
    websocket.onerror(() => errorDispatched.resolve());

    socket?.emitOpen();
    socket?.emitMessage(encodedMessage(3));
    socket?.emitError();

    await endStarted.promise;
    let errorObserved = false;
    void errorDispatched.promise.then(() => {
      errorObserved = true;
    });
    await Promise.resolve();
    expect(errorObserved).toBe(false);

    releaseEnd.resolve();
    await errorDispatched.promise;
  });
});
