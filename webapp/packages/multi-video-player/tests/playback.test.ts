import videojs from 'video.js';
import Component from 'video.js/dist/types/component';
import Player from 'video.js/dist/types/player';
import { ProgressManager } from '../src/progress-manager';
import { Percentage } from '../src/util';
import { MultiVideoPlayer, type PlaybackObservation, type SourceMetadata } from '../src/video-player/player';
import { MultiVideoProgressControl } from '../src/video-player/progress-control';

jest.mock('video.js', () => ({ __esModule: true, default: Object.assign(jest.fn(), { use: jest.fn() }) }));
jest.mock(
  'video.js/dist/types/player',
  () => ({
    __esModule: true,
    default: jest.fn(() => ({
      ready: jest.fn(),
      on: jest.fn(),
      trigger: jest.fn(),
      el: jest.fn(() => document.createElement('div')),
      off: jest.fn(),
      src: jest.fn(),
      currentTime: jest.fn(),
      duration: jest.fn(),
      paused: jest.fn(),
      pause: jest.fn(),
      play: jest.fn(),
      ended: jest.fn(),
      dispose: jest.fn(),
      error: jest.fn(),
      readyState: jest.fn(),
      seeking: jest.fn(),
      playbackRate: jest.fn(() => 1),
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
  const root = document.createElement('div');
  player.el.mockReturnValue(root);
  const state = {
    time: 0,
    duration: Number.POSITIVE_INFINITY,
    paused: true,
    metadataLoaded: false,
    readyState: 0,
    seeking: false,
    ended: false,
    automaticSeeked: true,
    zeroSeekTime: 0,
    seekTimeOverride: undefined as number | undefined,
  };
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
    state.readyState = 0;
    state.paused = true;
    state.ended = false;
    player.error.mockReturnValue(null);
    middleware.setSource(source, () => emit('sourceset', { src: source.src }));
    return undefined;
  });
  player.currentTime.mockImplementation((time) => {
    if (time !== undefined) {
      if (!state.metadataLoaded) {
        throw new Error('cannot seek before loadedmetadata');
      }
      state.time = Number(time) === 0 ? state.zeroSeekTime : (state.seekTimeOverride ?? Number(time));
      state.ended = false;
      state.seeking = true;
      emit('seeking');
      if (state.automaticSeeked) {
        queueMicrotask(() => {
          state.seeking = false;
          emit('seeked');
        });
      }
    }
    return state.time;
  });
  player.duration.mockImplementation(() => state.duration);
  player.readyState.mockImplementation(() => state.readyState);
  player.seeking.mockImplementation(() => state.seeking);
  player.paused.mockImplementation(() => state.paused);
  player.ended.mockImplementation(() => state.ended);
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
      state.readyState = 2;
      state.time = 0;
    }
    for (const callback of [...(listeners.get(type) ?? [])]) {
      callback.call(player, { type, ...event });
    }
  }

  return { player, play: player.play, state, progress, emit, listeners, root };
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
    },
  );

  it('continues the clock across three clips, including relative and repeated source URLs', async () => {
    const manager = await start(playlist.map((source) => ({ ...source, src: 'same.webm' })));
    fixture.state.time = 8;
    fixture.emit('timeupdate');
    expect(element.currentTime).toBe(8);
    fixture.state.time = 10.5;
    fixture.emit('ended');
    expect(element.currentClipIndex).toBe(0);
    expect(manager.currentPlayingHandle()).toBe(manager.handles[1]);
    expect(element.currentTime).toBe(10.5);
    fixture.emit('loadedmetadata');
    expect(element.currentTime).toBe(10.5);
    fixture.state.time = 12.25;
    fixture.emit('timeupdate');
    expect(element.currentTime).toBe(22.75);
    fixture.state.time = 20;
    fixture.emit('ended');
    fixture.emit('loadedmetadata');
    fixture.state.time = 5.5;
    fixture.emit('timeupdate');
    expect(element.currentTime).toBe(36);
    expect(element.currentClipIndex).toBe(2);
    fixture.state.time = 30.25;
    fixture.emit('ended');
    expect(element.currentTime).toBe(60.75);
    expect(element.currentClipIndex).toBe(2);
  });

  it('keeps metadata stable until the playlist is initialized again', async () => {
    const sources = playlist.slice(0, 2).map((source) => ({ ...source }));
    await start(sources);
    sources[0].duration = 100;
    sources[1].duration = 40;
    sources[1].src = 'updated.webm';

    const originalSeek = element.seek(15.5);
    fixture.emit('loadedmetadata');
    await originalSeek;
    expect(element.duration).toBe(30.5);
    expect(element.currentTime).toBe(15.5);
    expect(element.currentClipIndex).toBe(1);
    expect(fixture.state.time).toBe(5);
    expect(fixture.player.src).toHaveBeenLastCalledWith(expect.objectContaining({ src: playlist[1].src }));

    await element.play(sources);
    fixture.emit('loadedmetadata');
    const updatedSeek = element.seek(105);
    fixture.emit('loadedmetadata');
    await updatedSeek;
    expect(element.duration).toBe(140);
    expect(element.currentTime).toBe(105);
    expect(element.currentClipIndex).toBe(1);
    expect(fixture.state.time).toBe(5);
    expect(fixture.player.src).toHaveBeenLastCalledWith(expect.objectContaining({ src: 'updated.webm' }));
  });

  it('snapshots metadata provided through prototype getters', async () => {
    const source = new (class {
      get src() {
        return 'getters.webm';
      }
      get type() {
        return 'video/webm';
      }
      get duration() {
        return 10.5;
      }
    })();
    await start([source]);
    await element.seek(4.5);
    expect(element.duration).toBe(10.5);
    expect(element.currentTime).toBe(4.5);
    expect(fixture.player.src).toHaveBeenLastCalledWith(
      expect.objectContaining({ src: 'getters.webm', type: 'video/webm' }),
    );
  });

  it('uses linear seek work and constant-time clock reads for long playlists', async () => {
    const clipCount = 1000;
    const manager = await start(
      Array.from({ length: clipCount }, (_, index) => ({
        src: `clip-${index}.webm`,
        type: 'video/webm',
        duration: 1,
      })),
    );
    let handleReads = 0;
    manager.handles = new Proxy(manager.handles, {
      get(target, property, receiver) {
        if (typeof property === 'string' && /^\d+$/.test(property)) {
          handleReads++;
        }
        return Reflect.get(target, property, receiver);
      },
    });

    const seeking = element.seek(clipCount - 0.5);
    fixture.emit('loadedmetadata');
    await seeking;
    expect(element.currentClipIndex).toBe(clipCount - 1);
    expect(element.currentTime).toBe(clipCount - 0.5);
    expect(handleReads).toBeLessThan(10 * clipCount);

    handleReads = 0;
    for (let update = 0; update < 5; update++) {
      fixture.emit('timeupdate');
      expect(element.currentTime).toBe(clipCount - 0.5);
      expect(element.duration).toBe(clipCount);
    }
    expect(handleReads).toBeLessThan(50);
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
    expect(element.currentClipIndex).toBe(0);
    if (index !== 0) {
      expect(fixture.player.currentTime).not.toHaveBeenCalledWith(offset);
      fixture.emit('loadedmetadata');
    }
    await seek;
    if (offset !== 0) {
      expect(fixture.player.currentTime).toHaveBeenCalledWith(offset);
    }
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
    expect(original.handles[1].status).toEqual({ status: 'NotStarted' });
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

  // oracle: A rejected source selection must leave the still-loaded observation ready.
  it('restores readiness after seeking to an unsupported source', async () => {
    const observations: PlaybackObservation[] = [];
    element.addEventListener('timeupdate', (event) => observations.push(event.detail));
    await start();
    fixture.player.selectSource.mockReturnValueOnce(false);

    await expect(element.seek(12)).rejects.toThrow('no compatible source was found for this media');

    expect(observations[observations.length - 1]).toEqual({
      clipIndex: 0,
      localTime: 0,
      currentTime: 0,
      readiness: 'ready',
    });
  });

  it('preserves a newer seek issued by the restored observation listener', async () => {
    await start();
    fixture.player.selectSource.mockReturnValueOnce(false);
    let recovery: Promise<void> | undefined;
    element.addEventListener('timeupdate', (event) => {
      if (event.detail.readiness === 'ready' && event.detail.clipIndex === 0 && !recovery) {
        recovery = element.seek(5);
      }
    });

    await expect(element.seek(12)).rejects.toThrow('no compatible source was found for this media');
    await recovery;

    expect(element.currentClipIndex).toBe(0);
    expect(element.currentTime).toBeCloseTo(5);
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
    expect(times).toContainEqual(expect.objectContaining({ currentTime: 6, clipIndex: 0, localTime: 6 }));
    expect(times[times.length - 1]).toEqual({
      currentTime: 40,
      clipIndex: 2,
      localTime: 9.5,
      readiness: 'ready',
    });
  });

  // oracle: Mutating a public event detail must not mutate player state.
  it('isolates event details from the player observation', async () => {
    await start();
    await element.resume();
    fixture.state.time = 2;
    const mutateObservation = (observation: PlaybackObservation) => {
      observation.currentTime = 42;
      observation.clipIndex = 2;
      observation.readiness = 'ended';
    };
    const onTimeUpdate = (event: CustomEvent<PlaybackObservation>) => {
      mutateObservation(event.detail);
    };
    element.addEventListener('timeupdate', onTimeUpdate);

    fixture.emit('timeupdate');

    expect(element.currentTime).toBe(2);
    expect(element.currentClipIndex).toBe(0);
    expect(element.playing).toBe(true);

    element.removeEventListener('timeupdate', onTimeUpdate);
    element.addEventListener('clipchange', (event) => {
      mutateObservation(event.detail);
    });
    const seek = element.seek(12);
    fixture.emit('loadedmetadata');
    await seek;

    expect(element.currentTime).toBe(12);
    expect(element.currentClipIndex).toBe(1);
    expect(element.playing).toBe(true);
  });

  // oracle: The public playing state follows the held recording clock, not a native frame refresh.
  it('keeps logical playback active during a held-frame endpoint refresh seek', async () => {
    await start(playlist.slice(0, 1));
    await element.resume();
    fixture.state.duration = 9;
    fixture.state.time = 9;
    fixture.state.ended = true;
    fixture.emit('ended');
    fixture.state.seeking = true;
    fixture.emit('seeking');

    expect(element.playing).toBe(true);
  });

  it('keeps observations on the old source until the replacement metadata is available', async () => {
    const observations: PlaybackObservation[] = [];
    element.addEventListener('clipchange', (event) => observations.push(event.detail));
    element.addEventListener('timeupdate', (event) => observations.push(event.detail));
    await start();
    fixture.state.time = 8;
    fixture.emit('timeupdate');
    const seek = element.seek(15);
    expect(observations[observations.length - 1]).toEqual({
      clipIndex: 0,
      localTime: 8,
      currentTime: 8,
      readiness: 'loading',
    });
    expect(element.currentClipIndex).toBe(0);
    fixture.emit('loadedmetadata');
    await seek;
    expect(observations).toContainEqual({
      clipIndex: 1,
      localTime: 0,
      currentTime: playlist[0].duration,
      readiness: 'seeking',
    });
    expect(observations[observations.length - 1]).toEqual({
      clipIndex: 1,
      localTime: 4.5,
      currentTime: 15,
      readiness: 'ready',
    });
  });

  it('waits for seeked and current data before resolving a seek', async () => {
    await start();
    fixture.state.automaticSeeked = false;
    fixture.state.readyState = 1;
    let settled = false;
    const seeking = element.seek(7).then(() => {
      settled = true;
    });
    await Promise.resolve();
    expect(settled).toBe(false);
    fixture.emit('seeking');
    fixture.state.seeking = false;
    fixture.emit('seeked');
    await Promise.resolve();
    expect(settled).toBe(false);
    fixture.state.readyState = 2;
    fixture.emit('loadeddata');
    await seeking;
    expect(element.currentTime).toBeCloseTo(7);
  });

  // oracle: regression DVLS-15833
  it('settles a playing seek when playback advances before seeked', async () => {
    await start();
    await element.resume();
    fixture.state.automaticSeeked = false;
    let settled = false;
    const seeking = element.seek(7);
    void seeking.then(
      () => {
        settled = true;
      },
      () => {},
    );

    fixture.state.time = 7.011;
    fixture.state.seeking = false;
    fixture.emit('timeupdate');
    fixture.state.time = 7.012;
    fixture.emit('seeked');
    await new Promise((resolve) => setTimeout(resolve, 0));

    expect(settled).toBe(true);
    await seeking;
    expect(element.currentTime).toBeCloseTo(7.012);
    expect(fixture.state.paused).toBe(false);
  });

  // oracle: regression DVLS-15833
  it('settles an advanced seek after Pause interrupts playback', async () => {
    await start();
    await element.resume();
    fixture.state.automaticSeeked = false;
    const seeking = element.seek(7);
    fixture.state.time = 7.011;
    element.pause();
    fixture.state.seeking = false;
    fixture.emit('timeupdate');
    fixture.emit('seeked');

    await expect(seeking).resolves.toBeUndefined();
    expect(element.currentTime).toBeCloseTo(7.011);
    expect(fixture.state.paused).toBe(true);
  });

  // oracle: regression DVLS-15833
  it('advances after a playing clip ends while its seek is settling', async () => {
    const observations: PlaybackObservation[] = [];
    element.addEventListener('timeupdate', (event) => observations.push(event.detail));
    await start();
    await element.resume();
    fixture.state.automaticSeeked = false;
    const seeking = element.seek(10.49);
    fixture.state.time = 10.5;
    fixture.state.seeking = false;
    fixture.emit('timeupdate');
    fixture.emit('seeked');
    fixture.state.paused = true;
    fixture.state.ended = true;
    fixture.emit('ended');

    await seeking;

    expect(observations).toContainEqual(expect.objectContaining({ clipIndex: 0, localTime: 10.5, currentTime: 10.5 }));
    expect(fixture.player.src).toHaveBeenLastCalledWith(expect.objectContaining({ src: playlist[1].src }));
  });

  // oracle: regression DVLS-15833
  it('advances when Video.js pauses an ended clip while its seek is settling', async () => {
    await start();
    await element.resume();
    fixture.state.automaticSeeked = false;
    const seeking = element.seek(10.49);
    fixture.state.time = 10.5;
    fixture.state.seeking = false;
    fixture.emit('timeupdate');
    fixture.emit('seeked');
    fixture.state.ended = true;
    fixture.root.addEventListener(
      'ended',
      () => {
        fixture.player.pause();
        fixture.emit('ended');
      },
      { once: true },
    );
    fixture.root.dispatchEvent(new Event('ended', { bubbles: true }));

    await seeking;

    expect(fixture.player.src).toHaveBeenLastCalledWith(expect.objectContaining({ src: playlist[1].src }));
  });

  // oracle: regression DVLS-15833
  it('holds a paused endpoint when an ended event arrives before the seek settles', async () => {
    await start();
    fixture.state.duration = 7;
    fixture.state.automaticSeeked = false;
    const seeking = element.seek(8);
    fixture.state.ended = true;
    fixture.emit('ended');
    fixture.state.seeking = false;
    fixture.emit('seeked');

    await seeking;
    await element.resume();

    expect(fixture.state.paused).toBe(true);
    expect(element.currentTime).toBeCloseTo(8);
    expect(fixture.player.src).toHaveBeenCalledTimes(1);
  });

  // oracle: regression DVLS-15833
  it('does not advance after Pause while a seek and ended event are settling', async () => {
    await start();
    await element.resume();
    fixture.state.automaticSeeked = false;
    const seeking = element.seek(10.49);
    fixture.state.time = 10.5;
    fixture.state.seeking = false;
    fixture.emit('timeupdate');
    fixture.emit('seeked');
    fixture.state.paused = true;
    fixture.state.ended = true;
    fixture.emit('ended');
    element.pause();

    await seeking;

    expect(fixture.state.paused).toBe(true);
    expect(element.currentTime).toBe(10.5);
    expect(fixture.player.src).toHaveBeenCalledTimes(1);
  });

  // oracle: regression DVLS-15833
  it('discards a deferred ended event when its seek is superseded', async () => {
    await start();
    await element.resume();
    fixture.state.automaticSeeked = false;
    const first = element.seek(10.49);
    const cancelled = expect(first).rejects.toMatchObject({ name: 'AbortError' });
    fixture.state.time = 10.5;
    fixture.state.seeking = false;
    fixture.emit('timeupdate');
    fixture.emit('seeked');
    fixture.state.paused = true;
    fixture.state.ended = true;
    fixture.emit('ended');

    const latest = element.seek(3);
    fixture.state.seeking = false;
    fixture.emit('seeked');
    await cancelled;
    await latest;

    expect(element.currentTime).toBe(3);
    expect(fixture.state.paused).toBe(false);
    expect(fixture.player.src).toHaveBeenCalledTimes(1);
  });

  it('resolves a zero seek when the first media sample is slightly after zero', async () => {
    await start();
    fixture.state.zeroSeekTime = 0.001;
    fixture.state.time = 0.001;
    fixture.emit('timeupdate');
    const seeking = element.seek(0);
    await seeking;
    expect(element.currentTime).toBe(0.001);
  });

  // oracle: regression Devolutions/devolutions-gateway#2206
  it('settles a paused seek when media reports a rounded position', async () => {
    await start();
    fixture.state.automaticSeeked = false;
    fixture.state.seekTimeOverride = 4.124;

    const seeking = element.seek(4.123456);
    fixture.state.seeking = false;
    fixture.emit('timeupdate');
    fixture.emit('seeked');
    const settled = await Promise.race([
      seeking.then(
        () => true,
        () => false,
      ),
      new Promise<boolean>((resolve) => setTimeout(() => resolve(false), 0)),
    ]);

    expect(settled).toBe(true);
    expect(element.currentTime).toBe(4.124);
  });

  it('does not settle a superseding same-source seek from a stale seeked event', async () => {
    await start();
    fixture.state.automaticSeeked = false;
    const first = element.seek(4);
    const cancelled = expect(first).rejects.toMatchObject({ name: 'AbortError' });
    let settled = false;
    const latest = element.seek(7).then(() => {
      settled = true;
    });
    await cancelled;
    fixture.state.time = 4;
    fixture.state.seeking = false;
    fixture.emit('seeked');
    await Promise.resolve();
    expect(settled).toBe(false);
    fixture.state.time = 7;
    fixture.emit('seeked');
    await latest;
    expect(element.currentTime).toBe(7);
  });

  // oracle: regression DVLS-15833
  it('ignores a stale later-position seeked after a playing seek is superseded', async () => {
    await start();
    await element.resume();
    fixture.state.automaticSeeked = false;
    const first = element.seek(9);
    const cancelled = expect(first).rejects.toMatchObject({ name: 'AbortError' });
    let settled = false;
    const latest = element.seek(4).then(() => {
      settled = true;
    });
    await cancelled;
    fixture.state.time = 9;
    fixture.emit('timeupdate');
    fixture.state.seeking = false;
    fixture.emit('seeked');
    await new Promise((resolve) => setTimeout(resolve, 0));
    expect(settled).toBe(false);

    fixture.state.time = 4.011;
    fixture.emit('timeupdate');
    fixture.state.time = 4.012;
    fixture.emit('seeked');
    await latest;
    expect(element.currentTime).toBeCloseTo(4.012);
    expect(fixture.state.paused).toBe(false);
  });

  it('cancels a seek superseded by a seeking event listener', async () => {
    await start();
    let replacement: Promise<void> | undefined;
    let replaced = false;
    element.addEventListener('timeupdate', (event) => {
      if (event.detail.readiness === 'seeking' && !replaced) {
        replaced = true;
        replacement = element.seek(3);
      }
    });
    await expect(element.seek(7)).rejects.toMatchObject({ name: 'AbortError' });
    await replacement;
    expect(element.currentTime).toBeCloseTo(3);
  });

  it('clamps a paused seek to a shorter finite native duration without advancing', async () => {
    const events: PlaybackObservation[] = [];
    element.addEventListener('timeupdate', (event) => events.push(event.detail));
    await start();
    fixture.state.duration = 1;
    const seek = element.seek(17);
    fixture.emit('loadedmetadata');
    await seek;
    expect(fixture.state.time).toBe(1);
    expect(events[events.length - 1]).toEqual({
      clipIndex: 1,
      localTime: 1,
      clipDuration: 1,
      currentTime: 17,
      readiness: 'ready',
    });
    fixture.emit('ended');
    expect(element.currentClipIndex).toBe(1);
    expect(fixture.player.src).toHaveBeenCalledTimes(2);
  });

  // oracle: regression DVLS-15833
  it('advances recording time over a held frame before loading the next clip', async () => {
    jest.useFakeTimers({ doNotFake: ['queueMicrotask'] });
    try {
      const events: PlaybackObservation[] = [];
      element.addEventListener('timeupdate', (event) => events.push(event.detail));
      await start([
        { ...playlist[0], duration: 17 },
        { ...playlist[1], duration: 4 },
      ]);
      await element.resume();
      fixture.state.duration = 14.438;
      fixture.state.time = 14.438;
      fixture.state.paused = true;
      fixture.state.ended = true;
      fixture.emit('ended');
      await jest.advanceTimersByTimeAsync(1000);

      expect(element.currentTime).toBeCloseTo(15.438);
      expect(events[events.length - 1]).toMatchObject({
        localTime: 14.438,
        clipDuration: 14.438,
        readiness: 'ready',
      });
      expect(fixture.player.src).toHaveBeenCalledTimes(1);

      await jest.advanceTimersByTimeAsync(1562);
      expect(fixture.player.src).toHaveBeenCalledTimes(2);
      fixture.emit('loadedmetadata');
      expect(element.currentTime).toBe(17);
      expect(element.currentClipIndex).toBe(1);
    } finally {
      jest.useRealTimers();
    }
  });

  // oracle: regression DVLS-15833
  it('resumes and pauses the recording clock without restarting an exhausted video', async () => {
    jest.useFakeTimers({ doNotFake: ['queueMicrotask'] });
    try {
      const events: PlaybackObservation[] = [];
      element.addEventListener('timeupdate', (event) => events.push(event.detail));
      await start([{ ...playlist[0], duration: 14 }]);
      fixture.state.duration = 10.937;
      await element.seek(12);
      expect(element.currentTime).toBe(12);
      expect(fixture.state.time).toBe(10.937);
      expect(element.playing).toBe(false);

      await element.resume();
      expect(element.playing).toBe(true);
      await jest.advanceTimersByTimeAsync(550);
      element.pause();
      expect(element.playing).toBe(false);
      expect(element.currentTime).toBeCloseTo(12.55);
      await jest.advanceTimersByTimeAsync(1000);
      expect(element.currentTime).toBeCloseTo(12.55);

      await element.resume();
      await jest.advanceTimersByTimeAsync(1450);
      expect(element.currentTime).toBe(14);
      expect(element.playing).toBe(false);
      expect(events[events.length - 1].readiness).toBe('ended');
      expect(fixture.play).not.toHaveBeenCalled();
    } finally {
      jest.useRealTimers();
    }
  });

  // oracle: regression DVLS-15833
  it('seeks to distinct recording positions beyond the final native endpoint', async () => {
    const events: PlaybackObservation[] = [];
    element.addEventListener('timeupdate', (event) => events.push(event.detail));
    await start([17, 4, 4, 14].map((duration, index) => ({ ...playlist[0], src: `${index}.webm`, duration })));
    fixture.state.duration = 10.937;
    const first = element.seek(36);
    fixture.emit('loadedmetadata');
    await first;
    expect(element.currentTime).toBe(36);
    await element.seek(39);
    expect(events[events.length - 1]).toEqual({
      clipIndex: 3,
      localTime: 10.937,
      clipDuration: 10.937,
      currentTime: 39,
      readiness: 'ready',
    });
    expect(fixture.play).not.toHaveBeenCalled();
    expect(fixture.state.paused).toBe(true);
  });

  // oracle: regression DVLS-15833
  it('cancels the held clock when a playing seek moves back into video', async () => {
    await start([{ ...playlist[0], duration: 14 }]);
    fixture.state.duration = 10.937;
    await element.seek(12);
    jest.useFakeTimers({ doNotFake: ['queueMicrotask'] });
    try {
      await element.resume();
      await jest.advanceTimersByTimeAsync(500);
      await element.seek(3);
      await jest.advanceTimersByTimeAsync(5000);
      expect(element.currentTime).toBe(3);
      expect(fixture.state.time).toBe(3);
      expect(fixture.state.paused).toBe(false);
    } finally {
      jest.useRealTimers();
    }
  });

  // oracle: regression DVLS-15833
  it('applies playback-rate changes to a held frame without changing its media position', async () => {
    await start([{ ...playlist[0], duration: 14 }]);
    fixture.state.duration = 10.937;
    await element.seek(12);
    jest.useFakeTimers({ doNotFake: ['queueMicrotask'] });
    try {
      await element.resume();
      await jest.advanceTimersByTimeAsync(500);
      fixture.player.playbackRate.mockReturnValue(2);
      fixture.emit('ratechange');
      await jest.advanceTimersByTimeAsync(500);
      expect(element.currentTime).toBeCloseTo(13.5);
      expect(fixture.state.time).toBe(10.937);
    } finally {
      jest.useRealTimers();
    }
  });

  // oracle: regression DVLS-15833
  it('cancels the held clock when the player is disposed', async () => {
    await start([{ ...playlist[0], duration: 14 }]);
    fixture.state.duration = 10.937;
    await element.seek(12);
    jest.useFakeTimers({ doNotFake: ['queueMicrotask'] });
    try {
      await element.resume();
      const observed = jest.fn();
      element.addEventListener('timeupdate', observed);
      const disposed = element.dispose();
      await jest.advanceTimersByTimeAsync(5000);
      await disposed;
      expect(element.currentTime).toBe(0);
      expect(element.playing).toBe(false);
      expect(observed).not.toHaveBeenCalled();
    } finally {
      jest.useRealTimers();
    }
  });

  // oracle: regression DVLS-15833
  it('stops the held clock on media failure and rejects resume', async () => {
    await start([{ ...playlist[0], duration: 14 }]);
    fixture.state.duration = 10.937;
    await element.seek(12);
    jest.useFakeTimers({ doNotFake: ['queueMicrotask'] });
    try {
      await element.resume();
      fixture.emit('error');
      const stopped = element.currentTime;
      await jest.advanceTimersByTimeAsync(5000);
      expect(element.currentTime).toBe(stopped);
      expect(element.playing).toBe(false);
      await expect(element.resume()).rejects.toThrow('video source failed to load');
    } finally {
      jest.useRealTimers();
    }
  });

  // oracle: A failed media source must not resume through the player Play command.
  it('rejects Play after a held-frame media failure without restarting the clock', async () => {
    await start([{ ...playlist[0], duration: 14 }]);
    fixture.state.duration = 10.937;
    await element.seek(12);
    jest.useFakeTimers({ doNotFake: ['queueMicrotask'] });
    try {
      await element.resume();
      fixture.emit('error');
      const stopped = element.currentTime;

      await expect(fixture.player.play()).rejects.toThrow('video source failed to load');
      await jest.advanceTimersByTimeAsync(2000);

      expect(element.currentTime).toBe(stopped);
      expect(element.playing).toBe(false);
    } finally {
      jest.useRealTimers();
    }
  });

  // oracle: regression DVLS-15833
  it('preserves a newer Play issued by a paused held-frame observation', async () => {
    await start([{ ...playlist[0], duration: 14 }]);
    fixture.state.duration = 10.937;
    await element.seek(12);
    await element.resume();
    let replay: Promise<void> | undefined;
    element.addEventListener(
      'timeupdate',
      () => {
        if (!element.playing && !replay) {
          replay = element.resume();
        }
      },
      { once: true },
    );
    element.pause();
    await expect(replay).resolves.toBeUndefined();
    await element.seek(3);
    expect(fixture.state.paused).toBe(false);
  });

  // oracle: regression DVLS-15833
  it('does not publish the old held frame after its refresh listener seeks to another clip', async () => {
    const observations: PlaybackObservation[] = [];
    element.addEventListener('timeupdate', (event) => observations.push(event.detail));
    await start();
    fixture.state.duration = 9;
    fixture.state.time = 9;
    fixture.state.ended = true;
    let replaced = false;
    let replacement: Promise<void> | undefined;
    fixture.player.on('seeking', () => {
      if (!replaced) {
        replaced = true;
        replacement = element.seek(15);
      }
    });
    fixture.emit('ended');
    expect(observations[observations.length - 1].readiness).toBe('loading');
    fixture.emit('loadedmetadata');
    await replacement;
    expect(element.currentClipIndex).toBe(1);
    expect(element.currentTime).toBe(15);
  });

  it('holds a paused seek at the declared endpoint when resumed', async () => {
    await start();
    fixture.state.duration = 1;
    const seek = element.seek(element.duration);
    fixture.emit('loadedmetadata');
    await seek;

    fixture.play.mockImplementation(() => {
      fixture.state.time = 0;
      fixture.state.paused = false;
      fixture.emit('timeupdate');
      return Promise.resolve();
    });
    await element.resume();

    expect(fixture.state.paused).toBe(true);
    expect(element.currentClipIndex).toBe(2);
    expect(element.currentTime).toBe(element.duration);
  });

  // oracle: regression DVLS-15833
  it('keeps a paused endpoint after a seek to an unsupported source fails', async () => {
    await start();
    fixture.state.duration = 1;
    const seek = element.seek(element.duration);
    fixture.emit('loadedmetadata');
    await seek;

    fixture.player.selectSource.mockReturnValueOnce(false);
    await expect(element.seek(5)).rejects.toThrow('no compatible source was found for this media');
    fixture.play.mockImplementation(() => {
      fixture.state.time = 0;
      fixture.state.paused = false;
      fixture.emit('timeupdate');
      return Promise.resolve();
    });
    await element.resume();

    expect(fixture.state.paused).toBe(true);
    expect(element.currentClipIndex).toBe(2);
    expect(element.currentTime).toBe(element.duration);
  });

  it('publishes the observed uncued endpoint before loading the successor', async () => {
    jest.useFakeTimers({ doNotFake: ['queueMicrotask'] });
    try {
      const events: PlaybackObservation[] = [];
      element.addEventListener('timeupdate', (event) => events.push(event.detail));
      await start();
      fixture.state.time = 8.25;
      fixture.emit('ended');
      expect(fixture.player.src).toHaveBeenCalledTimes(1);
      await jest.advanceTimersByTimeAsync(2250);
      expect(events.slice(-2)).toEqual([
        {
          clipIndex: 0,
          localTime: 8.25,
          currentTime: 10.5,
          readiness: 'ready',
        },
        {
          clipIndex: 0,
          localTime: 8.25,
          currentTime: 10.5,
          readiness: 'loading',
        },
      ]);
      expect(fixture.player.src).toHaveBeenCalledTimes(2);
    } finally {
      jest.useRealTimers();
    }
  });

  it('marks the previous observation loading until the successor metadata arrives', async () => {
    const events: PlaybackObservation[] = [];
    element.addEventListener('timeupdate', (event) => events.push(event.detail));
    await start();
    fixture.state.time = 10.5;
    fixture.emit('timeupdate');

    fixture.emit('ended');

    expect(events.slice(-2)).toEqual([
      {
        clipIndex: 0,
        localTime: 10.5,
        currentTime: 10.5,
        readiness: 'ready',
      },
      {
        clipIndex: 0,
        localTime: 10.5,
        currentTime: 10.5,
        readiness: 'loading',
      },
    ]);

    fixture.emit('loadedmetadata');

    expect(events[events.length - 1]).toEqual({
      clipIndex: 1,
      localTime: 0,
      currentTime: playlist[0].duration,
      readiness: 'ready',
    });
  });

  it('keeps the previous observation non-ready when a successor source fails', async () => {
    const events: PlaybackObservation[] = [];
    element.addEventListener('timeupdate', (event) => events.push(event.detail));
    await start();
    fixture.state.time = 10.5;
    fixture.emit('timeupdate');

    fixture.emit('ended');
    fixture.emit('error');

    expect(events[events.length - 1]).toEqual({
      clipIndex: 0,
      localTime: 10.5,
      currentTime: 10.5,
      readiness: 'loading',
    });
    await expect(element.resume()).rejects.toThrow('video source failed to load');
  });

  it('does not autoplay a successor after Pause in the ending clip event', async () => {
    await start();
    await element.resume();
    fixture.play.mockClear();
    element.addEventListener('timeupdate', (event) => {
      if (event.detail.clipIndex === 0 && event.detail.localTime === 8) {
        element.pause();
      }
    });
    fixture.state.time = 8;
    fixture.emit('ended');
    fixture.emit('loadedmetadata');
    expect(fixture.play).not.toHaveBeenCalled();
    expect(fixture.state.paused).toBe(true);
  });

  // oracle: An explicit Pause command at a clip boundary must override automatic advance.
  it('honors direct Pause at a terminal observation during native ended dispatch', async () => {
    await start();
    await element.resume();
    fixture.play.mockClear();
    element.addEventListener('timeupdate', (event) => {
      if (event.detail.clipIndex === 0 && event.detail.currentTime === playlist[0].duration) {
        fixture.player.pause();
      }
    });
    fixture.state.time = playlist[0].duration;
    fixture.state.ended = true;
    fixture.root.addEventListener('ended', () => fixture.player.pause(), { once: true });
    fixture.root.addEventListener('ended', () => fixture.emit('ended'), { once: true });

    fixture.root.dispatchEvent(new Event('ended', { bubbles: true }));
    fixture.emit('loadedmetadata');

    expect(fixture.play).not.toHaveBeenCalled();
    expect(fixture.state.paused).toBe(true);
  });

  // oracle: regression DVLS-15833
  it('does not autoplay a successor when Pause precedes a queued ended event', async () => {
    await start();
    await element.resume();
    fixture.play.mockClear();
    element.pause();
    fixture.state.time = 10.5;
    fixture.state.ended = true;
    fixture.emit('ended');
    fixture.emit('loadedmetadata');

    expect(fixture.play).not.toHaveBeenCalled();
    expect(fixture.state.paused).toBe(true);
  });

  // oracle: regression DVLS-15833
  it('does not autoplay a successor when a control pauses before a queued ended event', async () => {
    await start();
    await element.resume();
    fixture.play.mockClear();
    fixture.player.pause();
    fixture.state.time = 10.5;
    fixture.state.ended = true;
    fixture.emit('ended');
    fixture.emit('loadedmetadata');

    expect(fixture.play).not.toHaveBeenCalled();
    expect(fixture.state.paused).toBe(true);
  });

  // oracle: regression DVLS-15833
  it('continues to the successor after Pause followed by Play', async () => {
    await start();
    await element.resume();
    element.pause();
    await element.resume();
    fixture.play.mockClear();
    fixture.state.time = 10.5;
    fixture.state.ended = true;
    fixture.emit('ended');
    fixture.emit('loadedmetadata');

    expect(fixture.play).toHaveBeenCalledTimes(1);
    expect(fixture.state.paused).toBe(false);
  });

  it('retains the final clip on completion and public resume restarts the playlist', async () => {
    const events: PlaybackObservation[] = [];
    element.addEventListener('timeupdate', (event) => events.push(event.detail));
    await start();
    fixture.state.time = 10.5;
    fixture.emit('ended');
    fixture.emit('loadedmetadata');
    fixture.state.time = 20;
    fixture.emit('ended');
    fixture.emit('loadedmetadata');
    fixture.state.duration = 12;
    fixture.state.time = 12;
    jest.useFakeTimers({ doNotFake: ['queueMicrotask'] });
    try {
      fixture.emit('ended');
      await jest.advanceTimersByTimeAsync(18250);
    } finally {
      jest.useRealTimers();
    }
    expect(events[events.length - 1]).toEqual({
      clipIndex: 2,
      localTime: 12,
      clipDuration: 12,
      currentTime: 60.75,
      readiness: 'ended',
    });
    expect(fixture.player.src).toHaveBeenCalledTimes(3);
    fixture.emit('timeupdate');
    expect(events[events.length - 1].readiness).toBe('ended');
    const replay = element.resume();
    fixture.emit('loadedmetadata');
    await replay;
    expect(element.currentClipIndex).toBe(0);
    expect(element.currentTime).toBe(0);
    expect(fixture.state.paused).toBe(false);
  });

  // oracle: regression DVLS-15833
  it('refreshes the frame at exact native EOF without reloading or playing the final clip', async () => {
    await start(playlist.slice(0, 1));
    fixture.state.duration = 9;
    fixture.state.time = 9;
    fixture.state.ended = true;
    fixture.emit('ended');
    await Promise.resolve();
    fixture.state.ended = true;
    fixture.emit('ended');

    const frameRequests = fixture.player.currentTime.mock.calls.filter(([time]) => time !== undefined);
    expect(frameRequests).toEqual([[9]]);
    expect(fixture.player.src).toHaveBeenCalledTimes(1);
    expect(fixture.play).not.toHaveBeenCalled();
  });

  // oracle: regression DVLS-15833
  it('waits for the native seek when selecting an event at an already-held native endpoint', async () => {
    await start(playlist.slice(0, 1));
    fixture.state.duration = 9;
    fixture.state.time = 9;
    fixture.state.ended = true;
    fixture.emit('ended');
    await Promise.resolve();
    fixture.player.currentTime.mockClear();
    fixture.state.automaticSeeked = false;

    let settled = false;
    const seek = element.seek(10.5).then(() => {
      settled = true;
    });
    await Promise.resolve();
    expect(fixture.player.currentTime).toHaveBeenCalledWith(9);
    expect(settled).toBe(false);
    fixture.state.seeking = false;
    fixture.emit('seeked');
    await seek;
    expect(fixture.state.paused).toBe(true);
    expect(fixture.play).not.toHaveBeenCalled();
  });

  // oracle: regression DVLS-15833
  it('keeps a seek paused after natural playlist completion', async () => {
    await start();
    await element.resume();
    for (const source of playlist.slice(0, -1)) {
      fixture.state.time = source.duration;
      fixture.emit('ended');
      fixture.emit('loadedmetadata');
    }
    fixture.state.time = playlist[2].duration;
    fixture.state.paused = true;
    fixture.emit('ended');
    fixture.play.mockClear();

    const seeking = element.seek(15);
    fixture.emit('loadedmetadata');
    await seeking;

    expect(element.currentClipIndex).toBe(1);
    expect(element.currentTime).toBe(15);
    expect(fixture.state.paused).toBe(true);
    expect(fixture.play).not.toHaveBeenCalled();
  });

  // oracle: regression DVLS-15833
  it('replays a single-clip playlist after natural completion', async () => {
    await start(playlist.slice(0, 1));
    await element.resume();
    fixture.state.time = playlist[0].duration;
    fixture.state.paused = true;
    fixture.emit('ended');

    await expect(element.resume()).resolves.toBeUndefined();
    expect(element.currentClipIndex).toBe(0);
    expect(element.currentTime).toBe(0);
    expect(fixture.state.paused).toBe(false);
  });

  // oracle: regression DVLS-15833
  it('keeps later seeks paused after seeking away from natural completion', async () => {
    await start(playlist.slice(0, 1));
    await element.resume();
    fixture.state.time = playlist[0].duration;
    fixture.state.paused = true;
    fixture.emit('ended');
    await element.seek(4);
    fixture.play.mockClear();

    await element.seek(5);

    expect(element.currentTime).toBeCloseTo(5);
    expect(fixture.state.paused).toBe(true);
    expect(fixture.play).not.toHaveBeenCalled();
  });

  // oracle: regression DVLS-15833
  it('keeps natural completion after a seek to an unsupported source fails', async () => {
    await start();
    fixture.state.time = playlist[0].duration;
    fixture.emit('ended');
    fixture.emit('loadedmetadata');
    fixture.state.time = playlist[1].duration;
    fixture.emit('ended');
    fixture.emit('loadedmetadata');
    fixture.state.time = playlist[2].duration;
    fixture.state.paused = true;
    fixture.emit('ended');

    fixture.player.selectSource.mockReturnValueOnce(false);
    await expect(element.seek(0)).rejects.toThrow('no compatible source was found for this media');
    const replay = element.resume();
    fixture.emit('loadedmetadata');
    await replay;

    expect(element.currentClipIndex).toBe(0);
    expect(element.currentTime).toBe(0);
    expect(fixture.state.paused).toBe(false);
  });

  it('honors Pause then Play while replay is loading its first clip', async () => {
    await start();
    fixture.state.time = playlist[0].duration;
    fixture.emit('ended');
    fixture.emit('loadedmetadata');
    fixture.state.time = playlist[1].duration;
    fixture.emit('ended');
    fixture.emit('loadedmetadata');
    fixture.state.time = playlist[2].duration;
    fixture.emit('ended');

    const firstReplay = element.resume();
    const interrupted = expect(firstReplay).rejects.toMatchObject({ name: 'AbortError' });
    element.pause();
    const replay = element.resume();
    fixture.emit('loadedmetadata');
    await replay;
    await interrupted;

    expect(element.currentClipIndex).toBe(0);
    expect(fixture.state.paused).toBe(false);
    expect(element.currentTime).toBe(0);
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

  // oracle: regression Devolutions/devolutions-gateway#2206
  it('resumes playback after a paused seek on a zero-duration clip', async () => {
    await start([{ ...playlist[0], duration: 0 }]);
    await element.seek(0);
    await element.resume();

    expect(fixture.state.paused).toBe(false);
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
