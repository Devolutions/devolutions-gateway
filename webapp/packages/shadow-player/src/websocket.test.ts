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

  binaryType: BinaryType = 'blob';
  readyState = FakeWebSocket.OPEN;
  onopen: ((event: Event) => void) | null = null;
  onmessage: ((event: MessageEvent) => void) | null = null;
  onclose: ((event: CloseEvent) => void) | null = null;
  onerror: ((event: Event) => void) | null = null;

  constructor(readonly url: string) {
    FakeWebSocket.latest = this;
  }

  send(): void {}

  close(): void {}

  emitMessage(data: ArrayBuffer): void {
    this.onmessage?.(new MessageEvent('message', { data }));
  }

  emitClose(): void {
    this.onclose?.(new CloseEvent('close', { code: 1006 }));
  }

  emitError(): void {
    this.onerror?.(new Event('error'));
  }
}

describe('ServerWebSocket', () => {
  beforeEach(() => {
    vi.stubGlobal('WebSocket', FakeWebSocket);
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    FakeWebSocket.latest = null;
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
      if (message.type === 'segment-started') {
        firstStarted.resolve();
        await releaseFirst.promise;
      } else {
        secondStarted.resolve();
      }
    }, vi.fn());
    websocket.onclose(() => closed.resolve());

    socket?.emitMessage(encodedMessage(1, '{"codec":"vp8","sequence":0,"width":640,"height":480}'));
    socket?.emitMessage(encodedMessage(0, 'chunk'));
    socket?.emitClose();

    await firstStarted.promise;
    await Promise.resolve();
    expect(calls).toEqual(['segment-started']);

    let closeDispatched = false;
    void closed.promise.then(() => {
      closeDispatched = true;
    });
    await Promise.resolve();
    expect(closeDispatched).toBe(false);

    releaseFirst.resolve();
    await secondStarted.promise;
    await closed.promise;
    expect(calls).toEqual(['segment-started', 'chunk']);
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
