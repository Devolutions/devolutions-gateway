// @vitest-environment jsdom

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { PlaybackClip } from './playbackClip';

class FakeSourceBuffer extends EventTarget {
  updating = false;

  appendBuffer(): void {
    if (this.updating) {
      throw new Error('concurrent append');
    }
    this.updating = true;
  }

  completeAppend(): void {
    this.updating = false;
    this.dispatchEvent(new Event('updateend'));
  }
}

class FakeMediaSource extends EventTarget {
  static latest: FakeMediaSource | null = null;

  readyState: ReadyState = 'closed';
  readonly sourceBuffer = new FakeSourceBuffer();
  endOfStreamCalls = 0;

  constructor() {
    super();
    FakeMediaSource.latest = this;
  }

  addSourceBuffer(): SourceBuffer {
    return this.sourceBuffer as unknown as SourceBuffer;
  }

  open(): void {
    this.readyState = 'open';
    this.dispatchEvent(new Event('sourceopen'));
  }

  endOfStream(): void {
    if (this.sourceBuffer.updating) {
      throw new Error('endOfStream during append');
    }
    this.endOfStreamCalls += 1;
    this.readyState = 'ended';
  }
}

describe('PlaybackClip', () => {
  beforeEach(() => {
    vi.stubGlobal('MediaSource', FakeMediaSource);
    vi.stubGlobal('URL', {
      createObjectURL: vi.fn(() => 'blob:test'),
      revokeObjectURL: vi.fn(),
    });
    vi.spyOn(HTMLMediaElement.prototype, 'pause').mockImplementation(() => {});
    vi.spyOn(HTMLMediaElement.prototype, 'load').mockImplementation(() => {});
  });

  afterEach(() => {
    vi.restoreAllMocks();
    vi.unstubAllGlobals();
    FakeMediaSource.latest = null;
  });

  it('waits for pending SourceBuffer work before ending the MediaSource', async () => {
    const clip = new PlaybackClip({
      codec: 'vp8',
      sequence: 0,
    });
    const mediaSource = FakeMediaSource.latest;
    expect(mediaSource).not.toBeNull();
    mediaSource?.open();
    await clip.open();

    const append = clip.append(new Uint8Array([1]));
    const finish = Promise.resolve().then(() => clip.finish());
    await Promise.resolve();
    await Promise.resolve();
    await Promise.resolve();
    expect(mediaSource?.sourceBuffer.updating).toBe(true);
    expect(mediaSource?.endOfStreamCalls).toBe(0);

    mediaSource?.sourceBuffer.completeAppend();
    await append;
    await finish;
    expect(mediaSource?.endOfStreamCalls).toBe(1);
  });

  it('rejects opening work on disposal and does not create a SourceBuffer afterward', async () => {
    const clip = new PlaybackClip({ codec: 'vp8', sequence: 0 });
    const opened = expect(clip.open()).rejects.toMatchObject({ name: 'AbortError' });
    const mediaSource = FakeMediaSource.latest;
    const add = mediaSource && vi.spyOn(mediaSource, 'addSourceBuffer');
    clip.dispose();
    await opened;
    mediaSource?.open();
    expect(add).not.toHaveBeenCalled();
    await expect(clip.append(new Uint8Array([1]))).rejects.toMatchObject({ name: 'AbortError' });
  });

  it('cancels a pending append and endOfStream work without waiting for updateend', async () => {
    const clip = new PlaybackClip({ codec: 'vp8', sequence: 0 });
    const mediaSource = FakeMediaSource.latest;
    mediaSource?.open();
    await clip.open();
    const appended = expect(clip.append(new Uint8Array([1]))).rejects.toMatchObject({ name: 'AbortError' });
    const finished = expect(clip.finish()).rejects.toMatchObject({ name: 'AbortError' });
    await Promise.resolve();
    await Promise.resolve();
    clip.dispose();
    await appended;
    await finished;
    expect(mediaSource?.endOfStreamCalls).toBe(0);
  });
});
