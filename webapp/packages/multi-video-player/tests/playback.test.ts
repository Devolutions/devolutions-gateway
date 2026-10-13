import videojs from 'video.js';
import Component from 'video.js/dist/types/component';
import Player from 'video.js/dist/types/player';
import { ProgressManager } from '../src/progress-manager';
import { Percentage } from '../src/util';
import { MultiVideoPlayer, type SourceMetadata } from '../src/video-player/player';
import { MultiVideoProgressControl } from '../src/video-player/progress-control';

jest.mock('video.js', () => ({ __esModule: true, default: Object.assign(jest.fn(), { use: jest.fn() }) }));
jest.mock(
  'video.js/dist/types/player',
  () => ({
    __esModule: true,
    default: jest.fn(() => ({
      ready: jest.fn(),
      on: jest.fn(),
      off: jest.fn(),
      src: jest.fn(),
      currentTime: jest.fn(),
      duration: jest.fn(),
      paused: jest.fn(),
      pause: jest.fn(),
      play: jest.fn(),
      dispose: jest.fn(),
      error: jest.fn(),
      readyState: jest.fn(),
      selectSource: jest.fn(() => ({})),
      getChild: jest.fn(),
    })),
  }),
  { virtual: true },
);
jest.mock(
  'video.js/dist/types/component',
  () => ({
    __esModule: true,
    default: jest.fn(() => ({ getChild: jest.fn() })),
  }),
  { virtual: true },
);
jest.mock('../src/video-player/progress-control', () => ({
  MultiVideoProgressControl: jest.fn(() => ({ setProgressManager: jest.fn() })),
}));

const playlist: SourceMetadata[] = [
  { src: 'first.webm', type: 'video/webm', duration: 10.5 },
  { src: 'second.webm', type: 'video/webm', duration: 20 },
  { src: 'third.webm', type: 'video/webm', duration: 30.25 },
];

const createMiddleware = jest.mocked(videojs.use).mock.calls[0][1];

function createPlayer() {
  const player = jest.mocked(new Player(document.createElement('video')));
  const listeners = new Map<string, Set<Parameters<Player['on']>[1]>>();
  const state = { time: 0, duration: Number.POSITIVE_INFINITY, paused: true, metadataLoaded: false };
  const progress = new MultiVideoProgressControl(player);
  const controlBar = jest.mocked(new Component(player));
  controlBar.getChild.mockReturnValue(progress);
  player.getChild.mockReturnValue(controlBar);
  player.ready.mockImplementation((callback) => {
    callback.call(player);
    return player;
  });
  player.on.mockImplementation((types, callback) => {
    for (const type of typeof types === 'string' ? [types] : types) {
      if (!listeners.has(type)) {
        listeners.set(type, new Set());
      }
      listeners.get(type)?.add(callback);
    }
  });
  player.off.mockImplementation((types, callback) => {
    for (const type of typeof types === 'string' ? [types] : types) {
      if (callback) {
        listeners.get(type)?.delete(callback);
      } else {
        listeners.delete(type);
      }
    }
  });
  const middleware: { setSource: (source: SourceMetadata, next: () => void) => void } = createMiddleware(player);
  player.src.mockImplementation((source: SourceMetadata) => {
    state.metadataLoaded = false;
    state.paused = true;
    player.error.mockReturnValue(null);
    middleware.setSource(source, () => emit('sourceset', { src: source.src }));
    return undefined;
  });
  player.currentTime.mockImplementation((time) => {
    if (time !== undefined) {
      if (!state.metadataLoaded) {
        throw new Error('cannot seek before loadedmetadata');
      }
      state.time = Number(time);
    }
    return state.time;
  });
  player.duration.mockImplementation(() => state.duration);
  player.readyState.mockImplementation(() => (state.metadataLoaded ? 1 : 0));
  player.paused.mockImplementation(() => state.paused);
  player.pause.mockImplementation(() => {
    state.paused = true;
  });
  player.play.mockImplementation(() => {
    state.paused = false;
    return Promise.resolve();
  });

  function emit(type: string, event = {}) {
    if (type === 'loadedmetadata') {
      state.metadataLoaded = true;
      state.time = 0;
    }
    for (const callback of [...(listeners.get(type) ?? [])]) {
      callback.call(player, event);
    }
  }

  return { player, play: player.play, state, progress, emit, listeners };
}

describe('recording playback API', () => {
  let fixture: ReturnType<typeof createPlayer>;
  let element: MultiVideoPlayer;

  beforeEach(() => {
    fixture = createPlayer();
    jest.mocked(videojs).mockReturnValue(fixture.player);
    const created = document.createElement('multi-video-player');
    if (!(created instanceof MultiVideoPlayer)) {
      throw new Error('multi-video-player was not registered');
    }
    element = created;
    document.body.appendChild(element);
  });

  afterEach(async () => {
    await element.dispose();
    element.remove();
    jest.clearAllMocks();
  });

  async function start(sources = playlist) {
    await element.play(sources);
    fixture.emit('loadedmetadata');
    return jest.mocked(fixture.progress.setProgressManager).mock.calls[0][0];
  }

  it('exposes empty clocks and resolves seek before play without loading a source', async () => {
    expect(element.currentTime).toBe(0);
    expect(element.duration).toBe(0);
    expect(element.currentClipIndex).toBe(-1);
    await expect(element.seek(12)).resolves.toBeUndefined();
    expect(fixture.player.src).not.toHaveBeenCalled();
  });

  it('resolves resume before play without loading a source or requesting playback', async () => {
    await expect(element.resume()).resolves.toBeUndefined();
    expect(fixture.player.src).not.toHaveBeenCalled();
    expect(fixture.play).not.toHaveBeenCalled();
  });

  it('resumes a paused recording without resetting its position or playlist', async () => {
    await start();
    await element.seek(7);
    const time = element.currentTime;
    const sources = fixture.player.src.mock.calls.length;
    await element.resume();
    expect(fixture.state.paused).toBe(false);
    expect(element.currentTime).toBe(time);
    expect(fixture.player.src).toHaveBeenCalledTimes(sources);
    expect(element.duration).toBe(60.75);
  });

  it('rejects resume after disposal instead of requesting playback', async () => {
    await start();
    await element.dispose();
    await expect(element.resume()).rejects.toMatchObject({ name: 'InvalidStateError' });
    expect(fixture.play).not.toHaveBeenCalled();
  });

  it('propagates synchronous and asynchronous playback failures from resume', async () => {
    await start();
    fixture.play.mockImplementationOnce(() => {
      throw new Error('playback unavailable');
    });
    await expect(element.resume()).rejects.toThrow('playback unavailable');
    fixture.play.mockRejectedValueOnce(new DOMException('autoplay denied', 'NotAllowedError'));
    await expect(element.resume()).rejects.toMatchObject({ name: 'NotAllowedError', message: 'autoplay denied' });
    await expect(element.resume()).resolves.toBeUndefined();
  });

  it('rejects pending resumes on media failure and permits a new source to recover', async () => {
    await start();
    fixture.play.mockReturnValue(new Promise<void>(() => {}));
    const first = element.resume();
    const second = element.resume();
    const firstFailure = expect(first).rejects.toThrow('video source failed to load');
    const secondFailure = expect(second).rejects.toThrow('video source failed to load');
    fixture.emit('error');
    await firstFailure;
    await secondFailure;
    await expect(element.resume()).rejects.toThrow('video source failed to load');
    expect(fixture.play).toHaveBeenCalledTimes(2);
    fixture.play.mockResolvedValue(undefined);
    const recovered = element.seek(40);
    fixture.emit('loadedmetadata');
    await recovered;
    await element.resume();
    expect(element.currentTime).toBe(40);
  });

  it('does not leave resume pending if destruction races a synchronous playback command', async () => {
    await start();
    fixture.play.mockImplementationOnce(() => {
      void element.dispose();
      return new Promise<void>(() => {});
    });
    await expect(element.resume()).rejects.toMatchObject({ name: 'AbortError' });
  });

  it.each([Number.NaN, Number.POSITIVE_INFINITY, Number.NEGATIVE_INFINITY])(
    'rejects non-finite seek time %s',
    async (time) => {
      await expect(element.seek(time)).rejects.toBeInstanceOf(RangeError);
    },
  );

  it.each([Number.NaN, Number.POSITIVE_INFINITY, -1])('rejects invalid source duration %s', async (duration) => {
    await expect(element.play([{ ...playlist[0], duration }])).rejects.toBeInstanceOf(RangeError);
    expect(fixture.player.src).not.toHaveBeenCalled();
  });

  it.each([Number.POSITIVE_INFINITY, Number.NaN, 999, 1])(
    'uses metadata instead of media duration %s for clocks and progress',
    async (duration) => {
      const manager = await start();
      fixture.state.duration = duration;
      fixture.state.time = 4.2;
      fixture.emit('timeupdate');
      expect(element.duration).toBe(60.75);
      expect(element.currentTime).toBe(4.2);
      expect(manager.handles[0].status).toEqual({
        status: 'playing',
        percentage: Percentage.devidedBy(4.2, 10.5),
      });
      expect(manager.handles[0].percentageToTime(Percentage.devidedBy(4.2, 10.5)).seconds).toBe(4);
      expect(fixture.player.duration).not.toHaveBeenCalled();
    },
  );

  it('continues the clock across three clips, including relative and repeated source URLs', async () => {
    const manager = await start(playlist.map((source) => ({ ...source, src: 'same.webm' })));
    fixture.state.time = 8;
    fixture.emit('timeupdate');
    expect(element.currentTime).toBe(8);
    fixture.emit('ended');
    expect(element.currentClipIndex).toBe(1);
    expect(manager.currentPlayingHandle()).toBe(manager.handles[1]);
    expect(element.currentTime).toBe(10.5);
    fixture.emit('loadedmetadata');
    fixture.state.time = 12.25;
    fixture.emit('timeupdate');
    expect(element.currentTime).toBe(22.75);
    fixture.emit('ended');
    fixture.emit('loadedmetadata');
    fixture.state.time = 5.5;
    fixture.emit('timeupdate');
    expect(element.currentTime).toBe(36);
    expect(element.currentClipIndex).toBe(2);
    fixture.emit('ended');
    expect(element.currentTime).toBe(0);
    expect(element.currentClipIndex).toBe(0);
  });

  it.each([
    [0, 0, 0],
    [10.5, 1, 0],
    [30.5, 2, 0],
    [40, 2, 9.5],
    [60.75, 2, 30.25],
    [-10, 0, 0],
    [100, 2, 30.25],
  ])('seeks recording time %s to clip %s at %s seconds', async (time, index, offset) => {
    const manager = await start();
    fixture.player.currentTime.mockClear();
    const seek = element.seek(time);
    expect(element.currentClipIndex).toBe(index);
    if (index !== 0) {
      expect(fixture.player.currentTime).not.toHaveBeenCalledWith(offset);
      fixture.emit('loadedmetadata');
    }
    await seek;
    expect(fixture.player.currentTime).toHaveBeenCalledWith(offset);
    expect(element.currentTime).toBe(manager.handles[index].startTime + offset);
    expect(manager.handles[index].status).toEqual({
      status: 'playing',
      percentage: Percentage.devidedBy(offset, playlist[index].duration),
    });
    expect(fixture.state.paused).toBe(true);
  });

  it('uses the same asynchronous seek path for progress-bar clicks', async () => {
    const manager = await start();
    const seek = manager.handles[2].userSeek(new Percentage(50));
    expect(fixture.player.currentTime).not.toHaveBeenCalledWith(15.125);
    fixture.emit('loadedmetadata');
    await seek;
    expect(element.currentTime).toBe(45.625);
    expect(manager.handles.map((handle) => handle.status)).toEqual([
      { status: 'ended' },
      { status: 'ended' },
      { status: 'playing', percentage: new Percentage(50) },
    ]);
  });

  it('waits for first-source metadata even for a same-clip seek', async () => {
    await element.play(playlist);
    const seek = element.seek(7);
    expect(fixture.player.currentTime).not.toHaveBeenCalledWith(7);
    fixture.emit('loadedmetadata');
    await seek;
    expect(element.currentTime).toBeCloseTo(7);
  });

  it.each([false, true])('preserves paused=%s across a source change', async (paused) => {
    await start();
    fixture.state.paused = paused;
    const seek = element.seek(15);
    fixture.emit('loadedmetadata');
    await seek;
    expect(fixture.state.paused).toBe(paused);
    expect(fixture.play).toHaveBeenCalledTimes(paused ? 0 : 1);
  });

  it('does not resume when pause is called while metadata is loading', async () => {
    await start();
    fixture.state.paused = false;
    const seek = element.seek(15);
    element.pause();
    fixture.emit('loadedmetadata');
    await seek;
    expect(fixture.state.paused).toBe(true);
    expect(fixture.play).not.toHaveBeenCalled();
  });

  it('resolves an applied seek when a newer Pause cancels its pending resume', async () => {
    await start();
    fixture.state.paused = false;
    fixture.play.mockReturnValueOnce(new Promise<void>(() => {}));
    const seek = element.seek(15);
    fixture.emit('loadedmetadata');
    element.pause();
    await seek;
    expect(element.currentTime).toBe(15);
    expect(fixture.state.paused).toBe(true);
  });

  it('rejects a superseded seek and applies only the latest offset while retaining playing intent', async () => {
    await start();
    fixture.state.paused = false;
    const first = element.seek(15);
    const rejected = expect(first).rejects.toMatchObject({ name: 'AbortError' });
    const second = element.seek(40);
    await rejected;
    fixture.emit('loadedmetadata');
    await second;
    expect(element.currentTime).toBe(40);
    expect(fixture.player.currentTime).not.toHaveBeenCalledWith(4.5);
    expect(fixture.state.paused).toBe(false);
    expect(fixture.listeners.get('error')?.size).toBe(1);
  });

  it('cancels a pending seek on playlist replacement without retaining old listeners', async () => {
    const original = await start();
    const seek = element.seek(15);
    const rejected = expect(seek).rejects.toMatchObject({ name: 'AbortError' });
    await element.play([playlist[2]]);
    await rejected;
    fixture.emit('loadedmetadata');
    fixture.state.time = 2;
    fixture.emit('timeupdate');
    expect(element.duration).toBe(30.25);
    expect(element.currentClipIndex).toBe(0);
    expect(element.currentTime).toBe(2);
    expect(original.handles[1].status).toEqual({ status: 'playing', percentage: new Percentage(22.5) });
    expect(fixture.listeners.get('timeupdate')?.size).toBe(1);
  });

  it('cancels pending seeks and clears clocks on disposal', async () => {
    await start();
    const seek = element.seek(15);
    const rejected = expect(seek).rejects.toMatchObject({ name: 'AbortError' });
    const disposed = element.dispose();
    await rejected;
    fixture.emit('loadedmetadata');
    await disposed;
    expect(element.currentTime).toBe(0);
    expect(element.duration).toBe(0);
    expect(element.currentClipIndex).toBe(-1);
    expect(fixture.player.dispose).toHaveBeenCalledTimes(1);
    expect([...fixture.listeners.values()].every((callbacks) => callbacks.size === 0)).toBe(true);
    await expect(element.seek(1)).rejects.toMatchObject({ name: 'InvalidStateError' });
  });

  it('cancels a seek while the resume promise is still pending', async () => {
    await start();
    fixture.state.paused = false;
    let resume!: () => void;
    fixture.play.mockReturnValueOnce(
      new Promise<void>((resolve) => {
        resume = resolve;
      }),
    );
    const first = element.seek(15);
    const rejected = expect(first).rejects.toMatchObject({ name: 'AbortError' });
    fixture.emit('loadedmetadata');
    const second = element.seek(40);
    await rejected;
    resume();
    fixture.emit('loadedmetadata');
    await second;
    expect(element.currentTime).toBe(40);
  });

  it('keeps only the latest same-source seek while metadata is loading', async () => {
    await start();
    const first = element.seek(15);
    const rejected = expect(first).rejects.toMatchObject({ name: 'AbortError' });
    const second = element.seek(20);
    await rejected;
    fixture.emit('loadedmetadata');
    await second;
    expect(element.currentTime).toBeCloseTo(20);
    expect(fixture.player.src).toHaveBeenCalledTimes(2);
    expect(fixture.player.currentTime).not.toHaveBeenCalledWith(4.5);
  });

  it('reports load and resume errors through the seek promise', async () => {
    await start();
    const loading = element.seek(15);
    const loadError = expect(loading).rejects.toThrow('video source failed to load');
    fixture.emit('error');
    await loadError;
    fixture.emit('loadedmetadata');
    fixture.state.paused = false;
    fixture.play.mockRejectedValueOnce(new Error('autoplay denied'));
    const seeking = element.seek(40);
    const playError = expect(seeking).rejects.toThrow('autoplay denied');
    fixture.emit('loadedmetadata');
    await playError;
    expect(fixture.listeners.get('error')?.size).toBe(1);
  });

  it('rejects a seek after the active source has already failed, but permits a replacement source', async () => {
    await element.play(playlist);
    fixture.emit('error');
    await expect(element.seek(5)).rejects.toThrow('video source failed to load');
    const replacement = element.seek(40);
    fixture.emit('loadedmetadata');
    await replacement;
    expect(element.currentTime).toBe(40);
  });

  it('dispatches typed DOM clock and clip events, without stale cross-clip offsets', async () => {
    const times: { currentTime: number; clipIndex: number }[] = [];
    const clips: number[] = [];
    element.addEventListener('timeupdate', (event) => {
      expect(event).toBeInstanceOf(CustomEvent);
      times.push(event.detail);
    });
    element.addEventListener('clipchange', (event) => {
      expect(event).toBeInstanceOf(CustomEvent);
      clips.push(event.detail.clipIndex);
    });
    await start();
    fixture.state.time = 6;
    fixture.emit('timeupdate');
    const seeking = element.seek(40);
    fixture.emit('timeupdate');
    fixture.emit('loadedmetadata');
    await seeking;
    expect(clips).toEqual([0, 2]);
    expect(times).toContainEqual({ currentTime: 6, clipIndex: 0 });
    expect(times[times.length - 1]).toEqual({ currentTime: 40, clipIndex: 2 });
    expect(times.filter((time) => time.clipIndex === 2).every((time) => time.currentTime === 40)).toBe(true);
  });

  it('clamps media offsets and handles zero-duration clips', async () => {
    const manager = await start([{ ...playlist[0], duration: 0 }, playlist[1]]);
    expect(manager.handles[0].getPercentageLength()).toBe(0);
    const seeking = element.seek(0);
    fixture.emit('loadedmetadata');
    await seeking;
    expect(element.currentClipIndex).toBe(1);
    fixture.state.time = 999;
    fixture.emit('durationchange');
    expect(element.currentTime).toBe(20);
    expect(manager.handles[1].status).toEqual({ status: 'playing', percentage: Percentage.full() });
    fixture.state.time = Number.NaN;
    fixture.emit('timeupdate');
    expect(element.currentTime).toBe(0);
    await element.play([{ ...playlist[0], duration: 0 }]);
    fixture.emit('loadedmetadata');
    await element.seek(5);
    expect(element.currentTime).toBe(0);
    expect(element.duration).toBe(0);
  });

  it('clamps fractional endpoint arithmetic before constructing a percentage', async () => {
    await start([
      { ...playlist[0], duration: 0.1 },
      { ...playlist[1], duration: 0.2 },
    ]);
    const seek = element.seek(element.duration);
    fixture.emit('loadedmetadata');
    await seek;
    expect(element.currentTime).toBeCloseTo(0.3);
  });

  it('does not start an awaiting play request after disposal', async () => {
    let ready!: () => void;
    fixture.player.ready.mockImplementation((callback) => {
      ready = () => callback.call(fixture.player);
      return fixture.player;
    });
    element.remove();
    await element.dispose();
    document.body.appendChild(element);
    const playing = element.play(playlist);
    await element.dispose();
    ready();
    await playing;
    expect(element.duration).toBe(0);
    expect(fixture.player.src).not.toHaveBeenCalled();
  });

  it('retains native event-listener removal and options', async () => {
    const listener = jest.fn();
    element.addEventListener('timeupdate', listener, { once: true });
    await start();
    fixture.emit('timeupdate');
    expect(listener).toHaveBeenCalledTimes(1);
    element.addEventListener('clipchange', listener);
    element.removeEventListener('clipchange', listener);
    const seek = element.seek(40);
    fixture.emit('loadedmetadata');
    await seek;
    expect(listener).toHaveBeenCalledTimes(1);
  });

  it('preserves an initialized playlist when play is called with an empty list', async () => {
    await start();
    const warning = jest.spyOn(console, 'warn').mockImplementation(() => {});
    await element.play([]);
    expect(element.duration).toBe(60.75);
    warning.mockRestore();
  });
});

it('allows a progress manager with no sources', async () => {
  const { player } = createPlayer();
  const manager = new ProgressManager(player, []);
  manager.start();
  await manager.seek(0);
  expect(manager.currentTime).toBe(0);
  expect(manager.duration).toBe(0);
  expect(manager.currentPlayingHandle()).toBeUndefined();
  manager.dispose();
});
