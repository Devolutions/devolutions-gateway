// @vitest-environment jsdom

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { ClientMessage, SegmentStartedMessage, ServerMessage } from './protocol';

interface MockServerWebSocket {
  sent: ClientMessage[];
  emitOpen: () => void;
  emitMessage: (message: ServerMessage) => Promise<void>;
  emitClose: (code?: number, reason?: string) => void;
  emitError: () => void;
}

interface MockPlaybackClip {
  metadata: SegmentStartedMessage;
  video: HTMLVideoElement;
  play: ReturnType<typeof vi.fn>;
  pause: ReturnType<typeof vi.fn>;
  open: ReturnType<typeof vi.fn>;
  append: ReturnType<typeof vi.fn>;
  finish: ReturnType<typeof vi.fn>;
  resolveOpen: () => void;
  resolveAppend: () => void;
  resolveFinish: () => void;
  setDuration: (duration: number) => void;
  loaded: () => void;
  end: () => void;
}

const mocks = vi.hoisted(() => ({
  sockets: [] as MockServerWebSocket[],
  clips: [] as MockPlaybackClip[],
}));

vi.mock('./websocket', () => ({
  ServerWebSocket: class {
    readonly sent: ClientMessage[] = [];
    private openCallback: (() => void) | null = null;
    private messageCallback: ((message: ServerMessage) => Promise<void> | void) | null = null;
    private closeCallback: ((event: CloseEvent) => void) | null = null;
    private errorCallback: ((event: Event) => void) | null = null;
    private failureCallback: ((error: unknown) => void) | null = null;

    constructor(_url: string) {
      mocks.sockets.push(this);
    }

    onopen(callback: () => void): void {
      this.openCallback = callback;
    }

    onmessage(callback: (message: ServerMessage) => Promise<void> | void, onFailure: (error: unknown) => void): void {
      this.messageCallback = callback;
      this.failureCallback = onFailure;
    }

    onclose(callback: (event: CloseEvent) => void): void {
      this.closeCallback = callback;
    }

    onerror(callback: (event: Event) => void): void {
      this.errorCallback = callback;
    }

    send(message: ClientMessage): void {
      this.sent.push(message);
    }

    isOpen(): boolean {
      return true;
    }

    close(): void {}

    emitOpen(): void {
      this.openCallback?.();
    }

    async emitMessage(message: ServerMessage): Promise<void> {
      try {
        await this.messageCallback?.(message);
      } catch (error) {
        this.failureCallback?.(error);
        throw error;
      }
    }

    emitClose(code = 1006, reason = ''): void {
      this.closeCallback?.(new CloseEvent('close', { code, reason, wasClean: false }));
    }

    emitError(): void {
      this.errorCallback?.(new Event('error'));
    }
  },
}));

vi.mock('./playbackClip', () => ({
  PlaybackClip: class {
    readonly video = document.createElement('video');
    readonly play = vi.fn(async () => undefined);
    readonly pause = vi.fn();
    readonly open: ReturnType<typeof vi.fn>;
    readonly append: ReturnType<typeof vi.fn>;
    readonly finish: ReturnType<typeof vi.fn>;
    private readonly openPromise: Promise<void>;
    private readonly appendPromise: Promise<void>;
    private readonly finishPromise: Promise<void>;
    private openResolver!: () => void;
    private appendResolver!: () => void;
    private finishResolver!: () => void;
    private duration = 0;
    private ended = false;

    constructor(readonly metadata: SegmentStartedMessage) {
      this.openPromise = new Promise((resolve) => {
        this.openResolver = resolve;
      });
      this.appendPromise = new Promise((resolve) => {
        this.appendResolver = resolve;
      });
      this.finishPromise = new Promise((resolve) => {
        this.finishResolver = resolve;
      });
      this.open = vi.fn(() => this.openPromise);
      this.append = vi.fn(() => this.appendPromise);
      this.finish = vi.fn(() => this.finishPromise);
      Object.defineProperties(this.video, {
        play: { configurable: true, value: this.play },
        pause: { configurable: true, value: this.pause },
        load: { configurable: true, value: vi.fn() },
        duration: { configurable: true, get: () => this.duration },
        ended: { configurable: true, get: () => this.ended },
      });
      mocks.clips.push(this);
    }

    resolveOpen(): void {
      this.openResolver();
    }

    resolveAppend(): void {
      this.appendResolver();
    }

    resolveFinish(): void {
      this.finishResolver();
    }

    setDuration(duration: number): void {
      this.duration = duration;
      this.video.dispatchEvent(new Event('durationchange'));
    }

    loaded(): void {
      this.video.dispatchEvent(new Event('loadeddata'));
    }

    end(): void {
      this.ended = true;
      this.video.dispatchEvent(new Event('ended'));
    }

    setDebug(): void {}

    downloadBufferedFile(): void {}

    dispose(): void {
      this.video.remove();
    }
  },
}));

import { ShadowPlayer } from './streamer';

async function flushMicrotasks(): Promise<void> {
  await Promise.resolve();
  await Promise.resolve();
  await Promise.resolve();
}

function createPlayer(attributes: string[] = []): { player: ShadowPlayer; socket: MockServerWebSocket } {
  const player = new ShadowPlayer();
  for (const attribute of attributes) {
    player.setAttribute(attribute, '');
  }
  player.setAttribute('src', 'ws://example.test');
  document.body.appendChild(player);
  const socket = mocks.sockets.at(-1);
  if (!socket) {
    throw new Error('ShadowPlayer did not create a websocket');
  }
  socket.emitOpen();
  return { player, socket };
}

const firstMetadata: SegmentStartedMessage = {
  type: 'segment-started',
  codec: 'vp8',
  sequence: 0,
  width: 640,
  height: 480,
};

const secondMetadata: SegmentStartedMessage = {
  type: 'segment-started',
  codec: 'vp8',
  sequence: 1,
  width: 1280,
  height: 720,
};

describe('ShadowPlayer', () => {
  beforeEach(() => {
    mocks.sockets.length = 0;
    mocks.clips.length = 0;
  });

  afterEach(() => {
    document.body.replaceChildren();
  });

  it('pulls only after segment and append work completes', async () => {
    const { player, socket } = createPlayer();
    const onEnd = vi.fn();
    player.onEnd(onEnd);
    expect(socket.sent).toEqual([{ type: 'start' }]);

    const firstStart = socket.emitMessage(firstMetadata);
    await flushMicrotasks();
    const firstClip = mocks.clips[0];
    expect(firstClip).toBeDefined();
    expect(socket.sent).toEqual([{ type: 'start' }]);

    firstClip.resolveOpen();
    await firstStart;
    expect(socket.sent).toEqual([{ type: 'start' }, { type: 'pull' }]);

    const chunk = socket.emitMessage({ type: 'chunk', data: new Uint8Array([1]) });
    await flushMicrotasks();
    expect(socket.sent).toHaveLength(2);
    firstClip.resolveAppend();
    await chunk;
    expect(socket.sent).toHaveLength(3);

    const secondStart = socket.emitMessage(secondMetadata);
    await flushMicrotasks();
    expect(firstClip.finish).toHaveBeenCalledOnce();
    expect(mocks.clips).toHaveLength(1);

    firstClip.resolveFinish();
    await flushMicrotasks();
    const secondClip = mocks.clips[1];
    expect(secondClip).toBeDefined();
    secondClip.resolveOpen();
    await secondStart;
    expect(socket.sent).toHaveLength(4);

    const streamEnd = socket.emitMessage({ type: 'stream-ended' });
    await flushMicrotasks();
    expect(secondClip.finish).toHaveBeenCalledOnce();
    expect(onEnd).not.toHaveBeenCalled();

    secondClip.resolveFinish();
    await streamEnd;
    expect(onEnd).toHaveBeenCalledOnce();
    expect(socket.sent).toHaveLength(4);
  });

  it('does not turn an abrupt close into a clean stream end', async () => {
    const { player, socket } = createPlayer();
    const onEnd = vi.fn();
    player.onEnd(onEnd);

    const start = socket.emitMessage(firstMetadata);
    await flushMicrotasks();
    const clip = mocks.clips[0];
    clip.resolveOpen();
    await start;

    socket.emitClose();
    expect(clip.finish).not.toHaveBeenCalled();
    expect(onEnd).not.toHaveBeenCalled();
  });

  it.each([4002, 4003, 1011])('surfaces unexpected close code %i', (code) => {
    const { player, socket } = createPlayer();
    const onError = vi.fn();
    player.onError(onError);

    socket.emitClose(code, `close ${code}`);

    expect(onError).toHaveBeenCalledOnce();
    expect(onError).toHaveBeenCalledWith({
      type: 'websocket-close',
      code,
      reason: `close ${code}`,
      wasClean: false,
    });
  });

  it('reports only the clean End when a socket error follows it', async () => {
    const { player, socket } = createPlayer();
    const onEnd = vi.fn();
    const onError = vi.fn();
    player.onEnd(onEnd);
    player.onError(onError);

    const start = socket.emitMessage(firstMetadata);
    await flushMicrotasks();
    const clip = mocks.clips[0];
    clip.resolveOpen();
    await start;

    const streamEnd = socket.emitMessage({ type: 'stream-ended' });
    await flushMicrotasks();
    clip.resolveFinish();
    await streamEnd;
    socket.emitError();

    expect(onEnd).toHaveBeenCalledOnce();
    expect(onError).not.toHaveBeenCalled();
  });

  it('rejects a noncontiguous segment sequence', async () => {
    const { socket } = createPlayer();

    await expect(socket.emitMessage({ ...firstMetadata, sequence: 1 })).rejects.toThrow(
      'Expected segment 0, received 1',
    );
    expect(mocks.clips).toHaveLength(0);
  });

  it('does not loop from stream completion while the next segment is not yet playable', async () => {
    const { player, socket } = createPlayer(['autoplay', 'loop']);

    const firstStart = socket.emitMessage(firstMetadata);
    await flushMicrotasks();
    const firstClip = mocks.clips[0];
    firstClip.resolveOpen();
    await firstStart;
    firstClip.loaded();
    expect(firstClip.play).toHaveBeenCalledOnce();

    const secondStart = socket.emitMessage(secondMetadata);
    await flushMicrotasks();
    firstClip.resolveFinish();
    await flushMicrotasks();
    const secondClip = mocks.clips[1];
    secondClip.resolveOpen();
    await secondStart;

    firstClip.end();
    const streamEnd = socket.emitMessage({ type: 'stream-ended' });
    await flushMicrotasks();
    secondClip.resolveFinish();
    await streamEnd;

    expect(player._videoElement).toBe(firstClip.video);
    expect(firstClip.play).toHaveBeenCalledOnce();
    expect(secondClip.play).not.toHaveBeenCalled();

    secondClip.loaded();
    expect(player._videoElement).toBe(secondClip.video);
    expect(firstClip.play).toHaveBeenCalledOnce();
    expect(secondClip.play).toHaveBeenCalledOnce();
  });

  it('does not show replay from the ended handler while the next segment is not yet playable', async () => {
    const { player, socket } = createPlayer(['autoplay']);

    const firstStart = socket.emitMessage(firstMetadata);
    await flushMicrotasks();
    const firstClip = mocks.clips[0];
    firstClip.resolveOpen();
    await firstStart;
    firstClip.loaded();

    const secondStart = socket.emitMessage(secondMetadata);
    await flushMicrotasks();
    firstClip.resolveFinish();
    await flushMicrotasks();
    const secondClip = mocks.clips[1];
    secondClip.resolveOpen();
    await secondStart;

    const streamEnd = socket.emitMessage({ type: 'stream-ended' });
    await flushMicrotasks();
    secondClip.resolveFinish();
    await streamEnd;
    firstClip.end();

    const replayButton = player.shadowRoot?.querySelector('.replay-button');
    expect(player._videoElement).toBe(firstClip.video);
    expect(replayButton?.classList.contains('visible')).toBe(false);
    expect(secondClip.play).not.toHaveBeenCalled();

    secondClip.loaded();
    expect(player._videoElement).toBe(secondClip.video);
    expect(secondClip.play).toHaveBeenCalledOnce();
    expect(replayButton?.classList.contains('visible')).toBe(false);
  });

  it('coordinates autoplay and loop across the full segment sequence', async () => {
    const { player, socket } = createPlayer(['autoplay', 'loop']);

    const firstStart = socket.emitMessage(firstMetadata);
    await flushMicrotasks();
    const firstClip = mocks.clips[0];
    firstClip.resolveOpen();
    await firstStart;

    const secondStart = socket.emitMessage(secondMetadata);
    await flushMicrotasks();
    firstClip.resolveFinish();
    await flushMicrotasks();
    const secondClip = mocks.clips[1];
    secondClip.resolveOpen();
    await secondStart;

    expect(firstClip.video.hasAttribute('autoplay')).toBe(false);
    expect(firstClip.video.hasAttribute('loop')).toBe(false);
    expect(secondClip.video.hasAttribute('autoplay')).toBe(false);
    expect(secondClip.video.hasAttribute('loop')).toBe(false);

    secondClip.loaded();
    expect(secondClip.play).not.toHaveBeenCalled();
    firstClip.loaded();
    expect(firstClip.play).toHaveBeenCalledOnce();

    firstClip.end();
    expect(player._videoElement).toBe(secondClip.video);
    expect(secondClip.play).toHaveBeenCalledOnce();

    const streamEnd = socket.emitMessage({ type: 'stream-ended' });
    await flushMicrotasks();
    secondClip.resolveFinish();
    await streamEnd;
    secondClip.end();

    expect(player._videoElement).toBe(firstClip.video);
    expect(firstClip.play).toHaveBeenCalledTimes(2);
    expect(player.shadowRoot?.querySelector('.replay-button')?.classList.contains('visible')).toBe(false);
  });

  it('keeps segment playback chronological while preserving pause, seek, and replay intent', async () => {
    const { player, socket } = createPlayer();

    const firstStart = socket.emitMessage(firstMetadata);
    await flushMicrotasks();
    const firstClip = mocks.clips[0];
    firstClip.resolveOpen();
    await firstStart;

    const secondStart = socket.emitMessage(secondMetadata);
    await flushMicrotasks();
    firstClip.resolveFinish();
    await flushMicrotasks();
    const secondClip = mocks.clips[1];
    secondClip.resolveOpen();
    await secondStart;

    firstClip.setDuration(10);
    secondClip.setDuration(20);
    secondClip.loaded();
    expect(player._videoElement).toBeNull();
    firstClip.loaded();
    expect(player._videoElement).toBe(firstClip.video);

    player.play();
    expect(firstClip.play).toHaveBeenCalledOnce();
    player.pause();
    firstClip.end();
    expect(player._videoElement).toBe(secondClip.video);
    expect(secondClip.play).not.toHaveBeenCalled();

    player.play();
    expect(secondClip.play).toHaveBeenCalledOnce();

    const firstTimelineSegment = player.shadowRoot?.querySelector<HTMLElement>('.timeline-segment');
    expect(firstTimelineSegment).not.toBeNull();
    vi.spyOn(firstTimelineSegment as HTMLElement, 'getBoundingClientRect').mockReturnValue({
      x: 0,
      y: 0,
      width: 100,
      height: 10,
      top: 0,
      right: 100,
      bottom: 10,
      left: 0,
      toJSON: () => ({}),
    });
    firstTimelineSegment?.dispatchEvent(new MouseEvent('click', { clientX: 25 }));
    expect(player._videoElement).toBe(firstClip.video);
    expect(firstClip.video.currentTime).toBe(2.5);
    expect(secondClip.video.currentTime).toBe(0);

    const streamEnd = socket.emitMessage({ type: 'stream-ended' });
    await flushMicrotasks();
    secondClip.resolveFinish();
    await streamEnd;

    firstClip.end();
    secondClip.end();
    const replayButton = player.shadowRoot?.querySelector<HTMLButtonElement>('.replay-button');
    expect(replayButton?.classList.contains('visible')).toBe(true);
    replayButton?.click();
    expect(player._videoElement).toBe(firstClip.video);
    expect(firstClip.video.currentTime).toBe(0);
    expect(secondClip.video.currentTime).toBe(0);
  });
});
