// @vitest-environment jsdom

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { PlaybackClipMetadata } from './playbackClip';
import type { ClientMessage, MetadataMessage, SegmentStartedMessage, ServerMessage } from './protocol';

interface MockServerWebSocket {
  sent: ClientMessage[];
  close: ReturnType<typeof vi.fn>;
  emitOpen: () => void;
  emitMessage: (message: ServerMessage) => Promise<void>;
  emitClose: (code?: number, reason?: string) => void;
  emitError: (event?: Event) => void;
}

interface MockPlaybackClip {
  metadata: PlaybackClipMetadata;
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
  setBuffered: (start: number, end: number) => void;
  setBufferedRanges: (ranges: Array<[number, number]>) => void;
  queuePlaybackEvents: () => void;
  userPause: () => void;
  userResume: () => void;
  userSeek: (time: number) => void;
  loaded: () => void;
  end: () => void;
}

const mocks = vi.hoisted(() => ({
  sockets: [] as MockServerWebSocket[],
  clips: [] as MockPlaybackClip[],
  protocolVersion: 'v2' as 'v1' | 'v2',
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

    shadowProtocolVersion(): 'v1' | 'v2' {
      return mocks.protocolVersion;
    }

    close = vi.fn();

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

    emitError(event: Event = new Event('error')): void {
      this.errorCallback?.(event);
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
    private paused = false;
    private bufferedRanges: Array<[number, number]> = [];

    constructor(readonly metadata: PlaybackClipMetadata) {
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
        paused: { configurable: true, get: () => this.paused },
        buffered: {
          configurable: true,
          get: () => ({
            length: this.bufferedRanges.length,
            start: (index: number) => this.bufferedRanges[index][0],
            end: (index: number) => this.bufferedRanges[index][1],
          }),
        },
      });
      mocks.clips.push(this);
    }

    setBuffered(start: number, end: number): void {
      this.bufferedRanges = [[start, end]];
    }

    setBufferedRanges(ranges: Array<[number, number]>): void {
      this.bufferedRanges = ranges;
    }

    queuePlaybackEvents(): void {
      this.play.mockImplementation(async () => {
        this.paused = false;
        queueMicrotask(() => this.video.dispatchEvent(new Event('play')));
      });
      this.pause.mockImplementation(() => {
        this.paused = true;
        queueMicrotask(() => this.video.dispatchEvent(new Event('pause')));
      });
    }

    userPause(): void {
      this.paused = true;
      this.video.dispatchEvent(new Event('pause'));
    }

    userResume(): void {
      this.paused = false;
      this.video.dispatchEvent(new Event('play'));
    }

    userSeek(time: number): void {
      this.paused = false;
      this.video.currentTime = time;
      this.video.dispatchEvent(new Event('seeked'));
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

const firstMetadata: MetadataMessage = {
  type: 'metadata',
  codec: 'vp8',
};

const secondMetadata: SegmentStartedMessage = {
  type: 'segment-started',
  codec: 'vp8',
};

describe('ShadowPlayer', () => {
  beforeEach(() => {
    mocks.sockets.length = 0;
    mocks.clips.length = 0;
  });

  afterEach(() => {
    document.body.replaceChildren();
    mocks.protocolVersion = 'v2';
    vi.restoreAllMocks();
  });

  it('exposes the negotiated shadow protocol for diagnostics', () => {
    mocks.protocolVersion = 'v1';
    const { player } = createPlayer();

    expect(player.dataset.shadowProtocol).toBe('v1');

    player.removeAttribute('src');
    expect(player.dataset.shadowProtocol).toBeUndefined();
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
    expect(firstClip.metadata).toEqual({ codec: 'vp8', sequence: 0 });
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
    expect(secondClip.metadata).toEqual({ codec: 'vp8', sequence: 1 });
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

  it('reopens the srcChange source after the element is reattached', () => {
    const player = new ShadowPlayer();
    document.body.appendChild(player);
    player.srcChange('ws://example.test');
    expect(mocks.sockets).toHaveLength(1);

    player.remove();
    document.body.appendChild(player);
    expect(mocks.sockets).toHaveLength(2);
    mocks.sockets[1].emitOpen();
    expect(mocks.sockets[1].sent).toEqual([{ type: 'start' }]);
  });

  it('does not reopen after the src attribute is removed', () => {
    const { player } = createPlayer();
    player.removeAttribute('src');

    player.remove();
    document.body.appendChild(player);
    expect(mocks.sockets).toHaveLength(1);
  });

  it('rejects a segment boundary before metadata', async () => {
    const { socket } = createPlayer();

    await expect(socket.emitMessage(secondMetadata)).rejects.toThrow('Received a segment boundary before metadata');
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

  async function startLiveClip(): Promise<{
    player: ShadowPlayer;
    socket: MockServerWebSocket;
    clip: MockPlaybackClip;
  }> {
    const { player, socket } = createPlayer();
    const start = socket.emitMessage(firstMetadata);
    await flushMicrotasks();
    const clip = mocks.clips[0];
    clip.resolveOpen();
    await start;
    clip.loaded();
    clip.resolveAppend();
    return { player, socket, clip };
  }

  const chunk: ServerMessage = { type: 'chunk', data: new Uint8Array([1]) };

  it('does not leak native event objects or reasons through any default SDK logger', () => {
    const secret = 'FAKE_SECRET_SENTINEL';
    const debugLog = vi.spyOn(console, 'debug').mockImplementation(() => {});
    const errorLog = vi.spyOn(console, 'error').mockImplementation(() => {});
    const warnLog = vi.spyOn(console, 'warn').mockImplementation(() => {});
    const infoLog = vi.spyOn(console, 'log').mockImplementation(() => {});
    const { player, socket } = createPlayer();
    player.srcChange(`ws://example.test/${secret}?token=${secret}`);
    const current = mocks.sockets[1];
    current.emitOpen();
    const event = new ErrorEvent('error', { message: secret, filename: secret });
    Object.defineProperty(event, 'target', { value: { url: `ws://example.test/?token=${secret}` } });
    current.emitError(event);
    current.emitClose(1006, secret);
    socket.emitClose(4001, secret);
    const logs = [...debugLog.mock.calls, ...errorLog.mock.calls, ...warnLog.mock.calls, ...infoLog.mock.calls];
    for (const args of logs) {
      for (const arg of args) {
        expect(typeof arg).toBe('string');
        expect(String(arg)).not.toContain(secret);
        expect(String(arg)).not.toContain('ws://');
        expect(String(arg)).not.toContain('token=');
      }
    }
    expect(errorLog).toHaveBeenCalledWith('Shadow playback failed:', 'websocket');
    expect(debugLog).not.toHaveBeenCalled();
  });

  it('preserves the public first-error outcome when close follows', () => {
    const { player, socket } = createPlayer();
    const error = vi.fn();
    const end = vi.fn();
    player.onError(error);
    player.onEnd(end);
    socket.emitError();
    socket.emitClose(4001, 'FAKE_SECRET_REASON');
    expect(error).toHaveBeenCalledOnce();
    expect(error).toHaveBeenCalledWith({ type: 'websocket', inner: expect.any(Event) });
    expect(end).not.toHaveBeenCalled();
  });

  it('does not deliver completion after an earlier transport error', async () => {
    const { player, socket } = createPlayer();
    const error = vi.fn();
    const end = vi.fn();
    player.onError(error);
    player.onEnd(end);
    socket.emitError();
    await socket.emitMessage({ type: 'stream-ended' });
    expect(error).toHaveBeenCalledOnce();
    expect(end).not.toHaveBeenCalled();
  });

  it('delivers clean End only after finalization and ignores later transport errors and close', async () => {
    const { player, socket, clip } = await startLiveClip();
    const end = vi.fn();
    const error = vi.fn();
    player.onEnd(end);
    player.onError(error);
    const ended = socket.emitMessage({ type: 'stream-ended' });
    await flushMicrotasks();
    expect(clip.finish).toHaveBeenCalledOnce();
    expect(end).not.toHaveBeenCalled();
    clip.resolveFinish();
    await ended;
    socket.emitError();
    socket.emitClose(1000);
    expect(end).toHaveBeenCalledOnce();
    expect(error).not.toHaveBeenCalled();
  });

  it('keeps an error-callback replacement connection owned through startup and disconnect', async () => {
    const { player, socket, clip } = await startLiveClip();
    const error = vi.fn(() => player.srcChange('ws://retry.test'));
    player.onError(error);
    clip.video.dispatchEvent(new Event('error'));
    expect(error).toHaveBeenCalledOnce();
    expect(socket.close).toHaveBeenCalledOnce();
    const replacement = mocks.sockets[1];
    expect(replacement.close).not.toHaveBeenCalled();
    replacement.emitOpen();
    expect(replacement.sent).toEqual([{ type: 'start' }]);
    player.disconnect();
    expect(replacement.close).toHaveBeenCalledOnce();
  });

  it('keeps protocol-failure recovery owned without closing the retry connection', async () => {
    const { player, socket } = createPlayer();
    player.onError(() => player.srcChange('ws://retry.test'));
    await expect(socket.emitMessage(secondMetadata)).rejects.toThrow('Received a segment boundary before metadata');
    const replacement = mocks.sockets[1];
    replacement.emitOpen();
    expect(replacement.sent).toEqual([{ type: 'start' }]);
    expect(replacement.close).not.toHaveBeenCalled();
    player.disconnect();
    expect(replacement.close).toHaveBeenCalledOnce();
  });

  it('allows an error callback to disconnect without a second close or retained events', async () => {
    const { player, socket, clip } = await startLiveClip();
    const error = vi.fn(() => player.disconnect());
    player.onError(error);
    clip.video.dispatchEvent(new Event('error'));
    expect(socket.close).toHaveBeenCalledOnce();
    expect(player._videoElement).toBeNull();
    clip.video.dispatchEvent(new Event('error'));
    expect(error).toHaveBeenCalledOnce();
  });

  it('keeps public Play newer than a queued native Pause notification', async () => {
    const { player, clip } = await startLiveClip();
    clip.queuePlaybackEvents();
    player.play();
    await flushMicrotasks();
    player.pause();
    player.play();
    expect(clip.video.paused).toBe(false);
    await flushMicrotasks();
    expect(clip.video.paused).toBe(false);
    expect(player.shadowRoot?.querySelector('button[aria-label="Pause"]')).not.toBeNull();
  });

  it('keeps public Pause newer than a queued native Play notification', async () => {
    const { player, clip } = await startLiveClip();
    clip.queuePlaybackEvents();
    player.play();
    player.pause();
    await flushMicrotasks();
    expect(clip.video.paused).toBe(true);
    expect(player.shadowRoot?.querySelector('button[aria-label="Play"]')).not.toBeNull();
  });

  it('does not move a playable paused clip across a newly buffered gap', async () => {
    const { player, socket, clip } = await startLiveClip();
    clip.queuePlaybackEvents();
    clip.setBuffered(0, 2);
    player.play();
    await flushMicrotasks();
    clip.video.currentTime = 2;
    player.pause();
    await flushMicrotasks();
    clip.setBufferedRanges([
      [0, 2],
      [8, 10],
    ]);
    await socket.emitMessage(chunk);
    expect(clip.video.currentTime).toBe(2);
    expect(clip.video.paused).toBe(true);
  });

  it.each([false, true])('reports retained-media errors after stream end with socket closed=%s', async (closed) => {
    const { player, socket, clip } = await startLiveClip();
    const end = vi.fn();
    const error = vi.fn();
    player.onEnd(end);
    player.onError(error);
    const ended = socket.emitMessage({ type: 'stream-ended' });
    await flushMicrotasks();
    clip.resolveFinish();
    await ended;
    if (closed) {
      socket.emitClose(1000);
    }
    clip.video.dispatchEvent(new Event('error'));
    expect(error).toHaveBeenCalledWith({
      type: 'player',
      inner: expect.objectContaining({ message: 'Video playback failed' }),
    });
    const lateError = vi.fn();
    player.onError(lateError, { replay: true });
    expect(lateError).toHaveBeenCalledOnce();
    const lateEnd = vi.fn();
    player.onEnd(lateEnd, { replay: true });
    expect(lateEnd).toHaveBeenCalledOnce();
    expect(end).toHaveBeenCalledOnce();
    player.disconnect();
    clip.video.dispatchEvent(new Event('error'));
    expect(lateError).toHaveBeenCalledOnce();
  });

  it('keeps controls disabled through readiness, end registration, and stream completion', async () => {
    const player = new ShadowPlayer();
    player.setControls(false);
    player.onEnd(vi.fn());
    player.setAttribute('src', 'ws://example.test');
    document.body.appendChild(player);
    const socket = mocks.sockets[0];
    socket.emitOpen();
    const start = socket.emitMessage(firstMetadata);
    await flushMicrotasks();
    const clip = mocks.clips[0];
    clip.resolveOpen();
    await start;
    clip.loaded();
    expect(player.shadowRoot?.querySelector('.control-bar')).toBeNull();
    expect(player.hasAttribute('controls')).toBe(false);
    expect(clip.video.controls).toBe(false);
    const ended = socket.emitMessage({ type: 'stream-ended' });
    await flushMicrotasks();
    clip.resolveFinish();
    await ended;
    clip.end();
    expect(player.shadowRoot?.querySelector('.replay-button.visible')).toBeNull();
    clip.video.click();
    expect(clip.play).not.toHaveBeenCalled();
    player.setControls(true);
    expect(player.shadowRoot?.querySelector('.control-bar')).not.toBeNull();
    player.setControls(false);
    expect(player.shadowRoot?.querySelector('.control-bar')).toBeNull();
  });

  it('announces playable readiness once and delivers readiness to late listeners', async () => {
    const { player, socket } = createPlayer(['autoplay']);
    const ready = vi.fn();
    player.onReady(ready);
    expect(ready).not.toHaveBeenCalled();
    const started = socket.emitMessage(firstMetadata);
    await flushMicrotasks();
    const clip = mocks.clips[0];
    clip.resolveOpen();
    await started;
    expect(ready).not.toHaveBeenCalled();
    clip.loaded();
    expect(ready).toHaveBeenCalledOnce();
    expect(clip.play).toHaveBeenCalledOnce();
    const lateReady = vi.fn();
    player.onReady(lateReady);
    expect(lateReady).toHaveBeenCalledOnce();
    player.play();
    expect(lateReady).toHaveBeenCalledOnce();
    player.disconnect();
    const afterDisconnect = vi.fn();
    player.onReady(afterDisconnect);
    expect(afterDisconnect).not.toHaveBeenCalled();
  });

  it('starts a playable clip inside its actual buffered range without overriding media duration', async () => {
    const { player, socket } = createPlayer(['autoplay']);
    const ready = vi.fn();
    player.onReady(ready);
    const started = socket.emitMessage(firstMetadata);
    await flushMicrotasks();
    const clip = mocks.clips[0];
    const duration = Object.getOwnPropertyDescriptor(clip.video, 'duration');
    clip.setDuration(Number.POSITIVE_INFINITY);
    clip.setBuffered(7, 9);
    clip.resolveOpen();
    await started;
    clip.loaded();
    expect(clip.video.currentTime).toBe(7);
    expect(clip.play).toHaveBeenCalledOnce();
    expect(ready).toHaveBeenCalledOnce();
    expect(Object.getOwnPropertyDescriptor(clip.video, 'duration')).toEqual(duration);
    expect(clip.video.duration).toBe(Number.POSITIVE_INFINITY);
  });

  it('moves inside the first buffered range before loadeddata so a nonzero-start stream can become playable', async () => {
    const { player, socket } = createPlayer(['autoplay']);
    const ready = vi.fn();
    player.onReady(ready);
    const started = socket.emitMessage(firstMetadata);
    await flushMicrotasks();
    const clip = mocks.clips[0];
    clip.resolveOpen();
    await started;
    clip.setBuffered(8, 10);
    clip.resolveAppend();
    await socket.emitMessage(chunk);
    expect(clip.video.currentTime).toBe(8);
    expect(ready).not.toHaveBeenCalled();
    expect(clip.play).not.toHaveBeenCalled();
    clip.loaded();
    expect(ready).toHaveBeenCalledOnce();
    expect(clip.play).toHaveBeenCalledOnce();
  });

  it('routes synchronous play and native media errors through the public callback', async () => {
    const { player, socket } = createPlayer(['autoplay']);
    const error = vi.fn();
    const ready = vi.fn();
    player.onError(error);
    player.onReady(ready);
    const started = socket.emitMessage(firstMetadata);
    await flushMicrotasks();
    const clip = mocks.clips[0];
    clip.play.mockImplementationOnce(() => {
      throw new Error('play failed');
    });
    clip.resolveOpen();
    await started;
    clip.loaded();
    expect(error).toHaveBeenCalledWith({ type: 'player', inner: expect.objectContaining({ message: 'play failed' }) });
    expect(ready).toHaveBeenCalledOnce();
    clip.video.dispatchEvent(new Event('error'));
    expect(error).toHaveBeenCalledWith({
      type: 'player',
      inner: expect.objectContaining({ message: 'Video playback failed' }),
    });
  });

  it('does not announce readiness after a synchronous playback-error callback disconnects the player', async () => {
    const { player, socket } = createPlayer(['autoplay']);
    const ready = vi.fn();
    player.onReady(ready);
    player.onError(() => player.disconnect());
    const started = socket.emitMessage(firstMetadata);
    await flushMicrotasks();
    const clip = mocks.clips[0];
    clip.play.mockImplementationOnce(() => {
      throw new Error('play failed');
    });
    clip.resolveOpen();
    await started;
    clip.loaded();
    expect(ready).not.toHaveBeenCalled();
    expect(player._videoElement).toBeNull();
  });

  it('suppresses stale autoplay rejection after the clip has been disconnected', async () => {
    const { player, socket } = createPlayer(['autoplay']);
    const error = vi.fn();
    player.onError(error);
    const started = socket.emitMessage(firstMetadata);
    await flushMicrotasks();
    const clip = mocks.clips[0];
    let reject!: (error: Error) => void;
    clip.play.mockReturnValueOnce(
      new Promise<void>((_resolve, rejectPromise) => {
        reject = rejectPromise;
      }),
    );
    clip.resolveOpen();
    await started;
    clip.loaded();
    player.disconnect();
    reject(new Error('old playback failed'));
    await flushMicrotasks();
    expect(error).not.toHaveBeenCalled();
    expect(player._videoElement).toBeNull();
  });

  it('uses buffered duration for the timeline even when media duration is longer', async () => {
    const { player, clip } = await startLiveClip();
    clip.setBuffered(0, 10);
    clip.setDuration(1000);
    const segment = player.shadowRoot?.querySelector<HTMLElement>('.timeline-segment');
    expect(segment?.style.flexGrow).toBe('10');
  });

  it('surfaces rejected autoplay and permits a public playback retry', async () => {
    const { player, socket } = createPlayer(['autoplay']);
    const error = vi.fn();
    player.onError(error);
    const started = socket.emitMessage(firstMetadata);
    await flushMicrotasks();
    const clip = mocks.clips[0];
    const denied = new DOMException('autoplay denied', 'NotAllowedError');
    clip.play.mockRejectedValueOnce(denied);
    clip.resolveOpen();
    await started;
    clip.loaded();
    await flushMicrotasks();
    expect(error).toHaveBeenCalledWith({ type: 'player', inner: denied });
    player.play();
    await flushMicrotasks();
    expect(clip.play).toHaveBeenCalledTimes(2);
  });

  it('does not report a stale playback rejection after a public Pause or disconnect', async () => {
    const { player, socket } = createPlayer(['autoplay']);
    const error = vi.fn();
    player.onError(error);
    const started = socket.emitMessage(firstMetadata);
    await flushMicrotasks();
    const clip = mocks.clips[0];
    let reject!: (error: Error) => void;
    clip.play.mockReturnValueOnce(
      new Promise<void>((_resolve, rejectPromise) => {
        reject = rejectPromise;
      }),
    );
    clip.resolveOpen();
    await started;
    clip.loaded();
    player.pause();
    reject(new DOMException('paused', 'AbortError'));
    await flushMicrotasks();
    expect(error).not.toHaveBeenCalled();
    player.disconnect();
    clip.loaded();
    expect(player._videoElement).toBeNull();
  });

  it('does not replay past end events unless requested', async () => {
    const { player, socket } = createPlayer();
    await socket.emitMessage({ type: 'stream-ended' });
    const end = vi.fn();
    player.onEnd(end);
    expect(end).not.toHaveBeenCalled();
    player.srcChange('ws://next.test');
    const next = mocks.sockets[1];
    next.emitOpen();
    await next.emitMessage({ type: 'stream-ended' });
    expect(end).toHaveBeenCalledOnce();
    player.onEnd(end);
    expect(end).toHaveBeenCalledOnce();
  });

  it('does not replay past errors unless requested', () => {
    const { player, socket } = createPlayer();
    vi.spyOn(console, 'error').mockImplementation(() => {});
    socket.emitClose(4001);
    const error = vi.fn();
    player.onError(error);
    expect(error).not.toHaveBeenCalled();
    player.srcChange('ws://next.test');
    const next = mocks.sockets[1];
    next.emitOpen();
    next.emitClose(4001);
    expect(error).toHaveBeenCalledOnce();
    player.onError(error);
    expect(error).toHaveBeenCalledOnce();
  });

  it.each([false, true])('accepts legacy value-returning end callbacks with async=%s', async (asynchronous) => {
    const { player, socket } = createPlayer();
    const events: string[] = [];
    const end = () => events.push('end');
    player.onEnd(asynchronous ? async () => end() : end);
    await socket.emitMessage({ type: 'stream-ended' });
    await flushMicrotasks();
    expect(events).toEqual(['end']);
  });

  it('replays retained end and session-not-found outcomes only when requested', async () => {
    const { player, socket } = createPlayer();
    const started = socket.emitMessage(firstMetadata);
    await flushMicrotasks();
    const clip = mocks.clips[0];
    clip.resolveOpen();
    await started;
    const ended = socket.emitMessage({ type: 'stream-ended' });
    await flushMicrotasks();
    clip.resolveFinish();
    await ended;
    const end = vi.fn();
    player.onEnd(end, { replay: true });
    expect(end).toHaveBeenCalledOnce();
    player.disconnect();
    const staleEnd = vi.fn();
    player.onEnd(staleEnd, { replay: true });
    expect(staleEnd).not.toHaveBeenCalled();

    const second = createPlayer();
    vi.spyOn(console, 'error').mockImplementation(() => {});
    second.socket.emitClose(4001);
    const error = vi.fn();
    second.player.onError(error, { replay: true });
    expect(error).toHaveBeenCalledWith({
      type: 'session-not-found',
      message: 'Recording session is no longer active',
    });
    second.player.srcChange('ws://retry.test');
    const staleError = vi.fn();
    second.player.onError(staleError, { replay: true });
    expect(staleError).not.toHaveBeenCalled();
    second.player.disconnect();
  });

  it('routes asynchronous end callback failures through the public error callback', async () => {
    const { player, socket, clip } = await startLiveClip();
    const error = vi.fn();
    player.onError(error);
    const failed = new Error('transition failed');
    player.onEnd(async () => {
      throw failed;
    });
    const ended = socket.emitMessage({ type: 'stream-ended' });
    await flushMicrotasks();
    clip.resolveFinish();
    await ended;
    await flushMicrotasks();
    expect(error).toHaveBeenCalledWith({ type: 'player', inner: failed });
  });

  it('does not send another pull after cancellation during an append', async () => {
    const { player, socket } = createPlayer();
    const started = socket.emitMessage(firstMetadata);
    await flushMicrotasks();
    const clip = mocks.clips[0];
    clip.resolveOpen();
    await started;
    const pending = socket.emitMessage(chunk);
    await flushMicrotasks();
    player.disconnect();
    clip.resolveAppend();
    await pending;
    expect(socket.sent).toEqual([{ type: 'start' }, { type: 'pull' }]);
    expect(player._videoElement).toBeNull();
  });

  it('jumps a live viewer to the live edge once data resumes after an idle screen', async () => {
    const { socket, clip } = await startLiveClip();
    clip.video.currentTime = 1.87;
    clip.setBuffered(0, 10.8);

    await socket.emitMessage(chunk);

    expect(clip.video.currentTime).toBeCloseTo(10.55);
  });

  it('stops following the live edge while paused or in history, and follows again near the edge', async () => {
    const { socket, clip } = await startLiveClip();
    clip.setBuffered(0, 12);

    clip.userPause();
    clip.video.currentTime = 2;
    await socket.emitMessage(chunk);
    expect(clip.video.currentTime).toBe(2);

    clip.userSeek(3);
    await socket.emitMessage(chunk);
    expect(clip.video.currentTime).toBe(3);

    clip.userSeek(11.5);
    clip.setBuffered(0, 20);
    clip.video.currentTime = 12;
    await socket.emitMessage(chunk);
    expect(clip.video.currentTime).toBeCloseTo(19.75);
  });

  it('follows the live edge again once a resumed viewer is back within the threshold', async () => {
    const { socket, clip } = await startLiveClip();
    clip.setBuffered(0, 12);
    clip.video.currentTime = 9;

    clip.userPause();
    clip.userResume();
    await socket.emitMessage(chunk);
    expect(clip.video.currentTime).toBe(9);

    clip.setBuffered(0, 20);
    await socket.emitMessage(chunk);
    expect(clip.video.currentTime).toBeCloseTo(19.75);
  });

  it('keeps a viewer that resumed far behind the live edge where it is', async () => {
    const { socket, clip } = await startLiveClip();
    clip.setBuffered(0, 12);
    clip.video.currentTime = 2;

    clip.userPause();
    clip.userResume();
    await socket.emitMessage(chunk);
    clip.setBuffered(0, 20);
    await socket.emitMessage(chunk);

    expect(clip.video.currentTime).toBe(2);
  });

  it('releases the media of the oldest segments beyond the retained limit', async () => {
    const { player, socket } = createPlayer();
    const start = socket.emitMessage(firstMetadata);
    await flushMicrotasks();
    mocks.clips[0].resolveOpen();
    await start;
    mocks.clips[0].setDuration(4);

    for (let sequence = 1; sequence <= 10; sequence++) {
      const next = socket.emitMessage(secondMetadata);
      await flushMicrotasks();
      mocks.clips[sequence - 1].resolveFinish();
      await flushMicrotasks();
      mocks.clips[sequence].resolveOpen();
      await next;
    }

    const container = player.shadowRoot?.querySelector('.container');
    expect(container?.contains(mocks.clips[0].video)).toBe(false);
    expect(container?.contains(mocks.clips[1].video)).toBe(true);
    const segments = player.shadowRoot?.querySelectorAll('.timeline-segment') ?? [];
    expect(segments).toHaveLength(11);
    expect(segments[0].getAttribute('aria-disabled')).toBe('true');
  });
});
