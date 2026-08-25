// @vitest-environment jsdom

import { describe, expect, it } from 'vitest';
import { ReactiveSourceBuffer } from './sourceBuffer';

class FakeSourceBuffer extends EventTarget {
  updating = false;
  readonly appended: Uint8Array[] = [];

  appendBuffer(buffer: BufferSource): void {
    if (this.updating) {
      throw new Error('concurrent append');
    }
    this.updating = true;
    const bytes =
      buffer instanceof ArrayBuffer
        ? new Uint8Array(buffer)
        : new Uint8Array(buffer.buffer, buffer.byteOffset, buffer.byteLength);
    this.appended.push(Uint8Array.from(bytes));
  }

  completeAppend(): void {
    this.updating = false;
    this.dispatchEvent(new Event('updateend'));
  }
}

describe('ReactiveSourceBuffer', () => {
  it('serializes append operations', async () => {
    const sourceBuffer = new FakeSourceBuffer();
    const mediaSource = {
      addSourceBuffer: () => sourceBuffer,
    } as unknown as MediaSource;
    const reactive = new ReactiveSourceBuffer(mediaSource, 'vp8');

    const first = reactive.appendBuffer(new Uint8Array([1]));
    const secondResult = reactive.appendBuffer(new Uint8Array([2])).then(
      () => null,
      (error: unknown) => error,
    );

    await Promise.resolve();
    expect(sourceBuffer.appended).toEqual([new Uint8Array([1])]);

    sourceBuffer.completeAppend();
    await first;
    await Promise.resolve();
    expect(sourceBuffer.appended).toEqual([new Uint8Array([1]), new Uint8Array([2])]);

    sourceBuffer.completeAppend();
    expect(await secondResult).toBeNull();
  });
});
