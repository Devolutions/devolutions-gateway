import type { ShadowPlayerError } from '@devolutions/shadow-player';
import { GatewayRecordingApi, type GatewayRecordingFileConfig } from '../src/gateway-api';
import { LiveRecordingStreamer } from '../src/live-streamer';
import type { MultiVideoPlayer } from '../src/video-player/player';

interface MockLivePlayer extends HTMLElement {
  controlsEnabled: boolean;
  srcChange: jest.Mock;
  play: jest.Mock;
  disconnect: jest.Mock;
  emitReady: () => void;
  emitEnd: () => void | Promise<void>;
  emitError: (error: ShadowPlayerError) => void;
}

const mockPlayers: MockLivePlayer[] = [];
let mockSourceAction: ((player: MockLivePlayer) => void) | null = null;
let mockLegacyPlayer = false;

jest.mock('@devolutions/shadow-player', () => {
  class MockShadowPlayer extends HTMLElement implements MockLivePlayer {
    controlsEnabled = true;
    private readyCallback?: () => void;
    private endCallback?: () => void;
    private errorCallback?: (error: ShadowPlayerError) => void;
    srcChange: jest.Mock = jest.fn((): void => mockSourceAction?.(this));
    play = jest.fn();
    disconnect = jest.fn();

    constructor() {
      super();
      if (mockLegacyPlayer) {
        Object.defineProperties(this, {
          setControls: { value: undefined },
          onReady: { value: undefined },
        });
      }
      mockPlayers.push(this);
    }

    setControls(controls: boolean) {
      this.controlsEnabled = controls;
      this.toggleAttribute('controls', controls);
    }

    onReady(callback: () => void) {
      this.readyCallback = callback;
    }
    onEnd(callback: () => void) {
      this.endCallback = callback;
    }
    onError(callback: (error: ShadowPlayerError) => void) {
      this.errorCallback = callback;
    }
    emitReady() {
      this.readyCallback?.();
    }
    emitEnd() {
      return this.endCallback?.();
    }
    emitError(error: ShadowPlayerError) {
      this.errorCallback?.(error);
    }
  }
  customElements.define('shadow-player', MockShadowPlayer);
  return { ShadowPlayer: MockShadowPlayer };
});

describe('public live recording stream', () => {
  let streamer: LiveRecordingStreamer;
  let container: HTMLDivElement;
  let api: GatewayRecordingApi;

  beforeEach(() => {
    mockPlayers.length = 0;
    mockSourceAction = null;
    mockLegacyPlayer = false;
    api = new GatewayRecordingApi('https://gateway.test', 'session', 'token');
    streamer = new LiveRecordingStreamer(api);
    container = document.createElement('div');
    document.body.appendChild(container);
  });

  afterEach(() => {
    streamer.disconnect();
    container.remove();
    jest.restoreAllMocks();
  });

  it('preserves default controls and resolves setup without waiting for playable data', async () => {
    const player = await streamer.stream(container);
    const mock = mockPlayers[0];
    expect(player).toBe(mock);
    expect(mock.controlsEnabled).toBe(true);
    expect(mock.getAttribute('width')).toBe('100%');
    expect(mock.getAttribute('height')).toBe('100%');
    expect(mock.srcChange).toHaveBeenCalledWith(api.getShadowUrl());
    expect(mock.play).toHaveBeenCalledTimes(1);
    expect(streamer.isConnected()).toBe(true);
  });

  it.each([false, true])('supports baseline ShadowPlayer with explicit controls=%s', async (explicitControls) => {
    mockLegacyPlayer = true;
    const player = await streamer.stream(container, explicitControls ? { controls: true } : undefined);
    const events: string[] = [];
    const errors: ShadowPlayerError[] = [];
    player.onEnd(() => events.push('end'));
    player.onError((error) => errors.push(error));
    const failure: ShadowPlayerError = { type: 'session-not-found', message: 'inactive' };

    expect(player.hasAttribute('controls')).toBe(true);
    expect(mockPlayers[0].srcChange).toHaveBeenCalledWith(api.getShadowUrl());
    expect(mockPlayers[0].play).toHaveBeenCalledTimes(1);
    await mockPlayers[0].emitEnd();
    mockPlayers[0].emitError(failure);
    expect(events).toEqual(['end']);
    expect(errors).toEqual([failure]);
    streamer.disconnect();
    expect(mockPlayers[0].disconnect).toHaveBeenCalledTimes(1);
    expect(container.childElementCount).toBe(0);
  });

  it.each([
    [{ controls: false }, 'controls: false'],
    [{ onReady: jest.fn() }, 'onReady'],
  ])('rejects unsupported new options on baseline ShadowPlayer: %s', async (options, feature) => {
    mockLegacyPlayer = true;
    await expect(streamer.stream(container, options)).rejects.toThrow(
      `Installed ShadowPlayer does not support ${feature}`,
    );
    expect(mockPlayers[0].disconnect).toHaveBeenCalledTimes(1);
    expect(mockPlayers[0].srcChange).not.toHaveBeenCalled();
    expect(mockPlayers[0].play).not.toHaveBeenCalled();
    expect(container.childElementCount).toBe(0);
    expect(streamer.isConnected()).toBe(false);
  });

  it('accepts value-returning callbacks in stream options', async () => {
    const events: string[] = [];
    await streamer.stream(container, {
      onReady: () => events.push('ready'),
      onEnd: async () => events.push('end'),
    });
    mockPlayers[0].emitReady();
    await mockPlayers[0].emitEnd();
    expect(events).toEqual(['ready', 'end']);
  });

  it('installs controls and callbacks before starting the source', async () => {
    const ready = jest.fn();
    const end = jest.fn();
    const error = jest.fn();
    const sessionNotFound = jest.fn();
    streamer.onSessionNotFound(sessionNotFound);
    const failure: ShadowPlayerError = { type: 'session-not-found', message: 'inactive' };
    mockSourceAction = (player) => {
      expect(player.controlsEnabled).toBe(false);
      player.emitReady();
      void player.emitEnd();
      player.emitError(failure);
    };
    await streamer.stream(container, { controls: false, onReady: ready, onEnd: end, onError: error });
    expect(ready).toHaveBeenCalledTimes(1);
    expect(end).toHaveBeenCalledTimes(1);
    expect(sessionNotFound).toHaveBeenCalledTimes(1);
    expect(error).toHaveBeenCalledWith(failure);
    expect(mockPlayers[0].hasAttribute('controls')).toBe(false);
  });

  it('cancels pending setup on disconnect without waiting for custom-element definition', async () => {
    jest.spyOn(customElements, 'whenDefined').mockReturnValueOnce(new Promise<CustomElementConstructor>(() => {}));
    const setup = streamer.stream(container);
    const cancelled = expect(setup).rejects.toMatchObject({ name: 'AbortError' });
    streamer.disconnect();
    await cancelled;
    expect(mockPlayers).toHaveLength(0);
    expect(streamer.isConnected()).toBe(false);
  });

  it('supersedes pending setup and does not clear the replacement instance', async () => {
    jest.spyOn(customElements, 'whenDefined').mockReturnValueOnce(new Promise<CustomElementConstructor>(() => {}));
    const first = streamer.stream(container);
    const cancelled = expect(first).rejects.toMatchObject({ name: 'AbortError' });
    const second = await streamer.stream(container, { controls: false });
    await cancelled;
    expect(mockPlayers).toHaveLength(1);
    expect(container.contains(second)).toBe(true);
    expect(streamer.isConnected()).toBe(true);
  });

  it('ignores late callbacks from a disconnected or replaced stream', async () => {
    const oldReady = jest.fn();
    const oldEnd = jest.fn();
    const oldError = jest.fn();
    const lost = jest.fn();
    streamer.onSessionNotFound(lost);
    await streamer.stream(container, { onReady: oldReady, onEnd: oldEnd, onError: oldError });
    const old = mockPlayers[0];
    const current = await streamer.stream(container);
    old.emitReady();
    await old.emitEnd();
    old.emitError({ type: 'session-not-found', message: 'old' });
    expect(oldReady).not.toHaveBeenCalled();
    expect(oldEnd).not.toHaveBeenCalled();
    expect(oldError).not.toHaveBeenCalled();
    expect(lost).not.toHaveBeenCalled();
    expect(old.disconnect).toHaveBeenCalledTimes(1);
    expect(container.contains(current)).toBe(true);
  });

  it('cleans up source setup failures and does not start playback', async () => {
    mockSourceAction = () => {
      throw new Error('source failed');
    };
    await expect(streamer.stream(container)).rejects.toThrow('source failed');
    expect(mockPlayers[0].disconnect).toHaveBeenCalledTimes(1);
    expect(mockPlayers[0].play).not.toHaveBeenCalled();
    expect(container.childElementCount).toBe(0);
    expect(streamer.isConnected()).toBe(false);
  });

  it('propagates URL construction failures without leaving pending setup', async () => {
    jest.spyOn(api, 'getShadowUrl').mockImplementationOnce(() => {
      throw new Error('invalid URL');
    });
    await expect(streamer.stream(container)).rejects.toThrow('invalid URL');
    expect(mockPlayers).toHaveLength(0);
    expect(streamer.isConnected()).toBe(false);
    await expect(streamer.stream(container)).resolves.toBeDefined();
  });

  it('preserves optional onError delivery even if session-not-found handling throws', async () => {
    const error = jest.fn();
    streamer.onSessionNotFound(() => {
      throw new Error('consumer failed');
    });
    const log = jest.spyOn(console, 'error').mockImplementation(() => {});
    mockSourceAction = (player) => player.emitError({ type: 'session-not-found', message: 'inactive' });
    await streamer.stream(container, { onError: error });
    expect(error).toHaveBeenCalledWith({ type: 'session-not-found', message: 'inactive' });
    expect(log).toHaveBeenCalledWith('Session-not-found callback failed');
  });

  it.each([false, true])(
    'does not deliver a stale error after session-not-found recovery with callback throwing=%s',
    async (throws) => {
      const log = jest.spyOn(console, 'error').mockImplementation(() => {});
      const error = jest.fn(() => streamer.disconnect());
      let replacement!: ReturnType<LiveRecordingStreamer['stream']>;
      streamer.onSessionNotFound(() => {
        replacement = streamer.stream(container);
        if (throws) {
          throw new Error('consumer failed after recovery');
        }
      });
      await streamer.stream(container, { onError: error });
      const old = mockPlayers[0];

      old.emitError({ type: 'session-not-found', message: 'inactive' });
      const recovered = await replacement;

      expect(error).not.toHaveBeenCalled();
      expect(old.disconnect).toHaveBeenCalledTimes(1);
      expect(container.childElementCount).toBe(1);
      expect(container.firstElementChild).toBe(recovered);
      expect(mockPlayers[1].play).toHaveBeenCalledTimes(1);
      expect(streamer.isConnected()).toBe(true);
      if (throws) {
        expect(log).toHaveBeenCalledWith('Session-not-found callback failed');
      } else {
        expect(log).not.toHaveBeenCalled();
      }
    },
  );

  it('does not deliver a stale error after session-not-found handling disconnects', async () => {
    const error = jest.fn();
    streamer.onSessionNotFound(() => streamer.disconnect());
    await streamer.stream(container, { onError: error });

    mockPlayers[0].emitError({ type: 'session-not-found', message: 'inactive' });

    expect(error).not.toHaveBeenCalled();
    expect(mockPlayers[0].disconnect).toHaveBeenCalledTimes(1);
    expect(container.childElementCount).toBe(0);
    expect(streamer.isConnected()).toBe(false);
  });

  it('logs only an error category when no live error callback is configured', async () => {
    const secret = 'FAKE_SECRET_SENTINEL';
    const log = jest.spyOn(console, 'error').mockImplementation(() => {});
    const event = new ErrorEvent('error', { message: secret, filename: secret });
    Object.defineProperty(event, 'target', { value: { url: `ws://example.test/?token=${secret}` } });
    await streamer.stream(container);
    mockPlayers[0].emitError({ type: 'websocket', inner: event });
    expect(log).toHaveBeenCalledWith('Live recording failed:', 'websocket');
    for (const args of log.mock.calls) {
      for (const arg of args) {
        expect(typeof arg).toBe('string');
        expect(String(arg)).not.toContain(secret);
      }
    }
  });

  it('does not log a secret-bearing transition failure object or message', async () => {
    const secret = 'FAKE_SECRET_SENTINEL';
    const log = jest.spyOn(console, 'error').mockImplementation(() => {});
    jest.spyOn(api, 'fetchMetadata').mockRejectedValue(new Error(`ws://example.test/?token=${secret}`));
    const staticPlayer: Pick<MultiVideoPlayer, 'play'> = { play: jest.fn().mockResolvedValue(undefined) };
    await streamer.streamAndTransition(container, staticPlayer);
    await mockPlayers[0].emitEnd();
    expect(log).toHaveBeenCalledWith('Live recording transition failed');
    expect(log.mock.calls.flat().join('\n')).not.toContain(secret);
    expect(staticPlayer.play).not.toHaveBeenCalled();
  });

  it('does not restart playback when an early callback disconnects the streamer', async () => {
    mockSourceAction = (player) => player.emitError({ type: 'session-not-found', message: 'inactive' });
    await expect(streamer.stream(container, { onError: () => streamer.disconnect() })).rejects.toMatchObject({
      name: 'AbortError',
    });
    expect(mockPlayers[0].play).not.toHaveBeenCalled();
    expect(streamer.isConnected()).toBe(false);
  });

  it.each([false, true])('retains live-to-saved transition with baseline ShadowPlayer=%s', async (legacy) => {
    mockLegacyPlayer = legacy;
    const metadata: GatewayRecordingFileConfig = {
      sessionId: 'session',
      startTime: 0,
      duration: 10,
      files: [{ fileName: 'saved.webm', startTime: 0, duration: 10 }],
    };
    jest.spyOn(api, 'fetchMetadata').mockResolvedValue(metadata);
    const staticPlayer: Pick<MultiVideoPlayer, 'play'> = { play: jest.fn().mockResolvedValue(undefined) };
    await streamer.streamAndTransition(container, staticPlayer);
    await mockPlayers[0].emitEnd();
    expect(container.childElementCount).toBe(0);
    expect(staticPlayer.play).toHaveBeenCalledWith([
      {
        src: api.getSegmentUrl('saved.webm'),
        type: 'video/webm',
        duration: 10,
      },
    ]);
  });

  it('does not apply fetched saved metadata after disconnect', async () => {
    let resolve!: (metadata: GatewayRecordingFileConfig) => void;
    jest.spyOn(api, 'fetchMetadata').mockReturnValue(
      new Promise((accept) => {
        resolve = accept;
      }),
    );
    const staticPlayer: Pick<MultiVideoPlayer, 'play'> = { play: jest.fn().mockResolvedValue(undefined) };
    await streamer.streamAndTransition(container, staticPlayer);
    const transition = mockPlayers[0].emitEnd();
    streamer.disconnect();
    resolve({ sessionId: 'session', startTime: 0, duration: 0, files: [] });
    await transition;
    expect(staticPlayer.play).not.toHaveBeenCalled();
  });
});
