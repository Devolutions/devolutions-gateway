import videojs from 'video.js';
import type PlayToggle from 'video.js/dist/types/control-bar/play-toggle';
import { MultiVideoPlayer } from '../src/video-player/player';

const sources = [
  { src: 'first.webm', type: 'video/webm', duration: 10 },
  { src: 'second.webm', type: 'video/webm', duration: 20 },
  { src: 'third.webm', type: 'video/webm', duration: 30 },
];

describe('video.js media lifecycle', () => {
  let element: MultiVideoPlayer;
  let player: ReturnType<typeof videojs>;
  let media: HTMLVideoElement;
  let metadataReady: boolean;
  let paused: boolean;
  let css: PropertyDescriptor | undefined;

  beforeEach(async () => {
    css = Object.getOwnPropertyDescriptor(window, 'CSS');
    Object.defineProperty(window, 'CSS', { configurable: true, value: { supports: () => false } });
    metadataReady = false;
    paused = true;
    jest.spyOn(HTMLMediaElement.prototype, 'canPlayType').mockReturnValue('probably');
    jest.spyOn(HTMLMediaElement.prototype, 'load').mockImplementation(() => {});
    jest.spyOn(HTMLMediaElement.prototype, 'readyState', 'get').mockImplementation(() => (metadataReady ? 1 : 0));
    jest.spyOn(HTMLMediaElement.prototype, 'paused', 'get').mockImplementation(() => paused);
    jest.spyOn(HTMLMediaElement.prototype, 'pause').mockImplementation(function (this: HTMLMediaElement) {
      paused = true;
      this.dispatchEvent(new Event('pause'));
    });
    jest.spyOn(HTMLMediaElement.prototype, 'play').mockImplementation(function (this: HTMLMediaElement) {
      paused = false;
      this.dispatchEvent(new Event('play'));
      return Promise.resolve();
    });
    element = new MultiVideoPlayer();
    document.body.appendChild(element);
    const created = videojs.getPlayer('my-video');
    if (!created) {
      throw new Error('video.js player was not created');
    }
    player = created;
    player.on('sourceset', () => {
      metadataReady = false;
      player.el().querySelector('video')?.pause();
    });
    await new Promise<void>((resolve) => player.ready(resolve));
    const video = player.el().querySelector('video');
    if (!(video instanceof HTMLVideoElement)) {
      throw new Error('video.js media element was not created');
    }
    media = video;
  });

  afterEach(async () => {
    await element.dispose();
    element.remove();
    jest.restoreAllMocks();
    if (css) {
      Object.defineProperty(window, 'CSS', css);
    } else {
      Reflect.deleteProperty(window, 'CSS');
    }
  });

  function sourceSet() {
    return new Promise<void>((resolve) => player.one('sourceset', () => resolve()));
  }

  function loadedMetadata() {
    metadataReady = true;
    media.currentTime = 0;
    media.dispatchEvent(new Event('loadedmetadata'));
  }

  async function start(playlist = sources) {
    const installed = sourceSet();
    await element.play(playlist);
    await installed;
    loadedMetadata();
  }

  it.each(['clipchange', 'timeupdate'] as const)(
    'keeps a successor paused when its %s callback requests Pause',
    async (eventName) => {
      await start();
      await element.resume();
      jest.mocked(HTMLMediaElement.prototype.play).mockClear();
      element.addEventListener(eventName, (event) => {
        if (event.detail.clipIndex === 1) {
          element.pause();
        }
      });
      const installed = sourceSet();
      media.dispatchEvent(new Event('ended'));
      await installed;
      media.dispatchEvent(new Event('loadstart'));
      loadedMetadata();
      await Promise.resolve();
      expect(element.currentClipIndex).toBe(1);
      expect(paused).toBe(true);
      expect(HTMLMediaElement.prototype.play).not.toHaveBeenCalled();
    },
  );

  it('continues successor playback when transition callbacks do not issue a newer command', async () => {
    await start();
    await element.resume();
    jest.mocked(HTMLMediaElement.prototype.play).mockClear();
    const installed = sourceSet();
    media.dispatchEvent(new Event('ended'));
    await installed;
    media.dispatchEvent(new Event('loadstart'));
    loadedMetadata();
    await Promise.resolve();
    expect(paused).toBe(false);
    expect(element.currentClipIndex).toBe(1);
    expect(HTMLMediaElement.prototype.play).toHaveBeenCalledTimes(1);
  });

  async function nativeAutoplay() {
    if (media.autoplay) {
      paused = false;
      queueMicrotask(() => media.dispatchEvent(new Event('play')));
      await Promise.resolve();
    }
  }

  it('preserves native autoplay for the initial source before any Pause command', async () => {
    element.setAttribute('autoplay', '');
    element.setAttribute('muted', '');
    player.autoplay(true);
    await start();
    await nativeAutoplay();
    expect(media.autoplay).toBe(true);
    expect(paused).toBe(false);
  });

  it.each(['clipchange', 'timeupdate'] as const)(
    'honors public Pause from %s even when the native successor autoplays',
    async (eventName) => {
      element.setAttribute('autoplay', '');
      element.setAttribute('muted', '');
      player.autoplay(true);
      await start();
      await nativeAutoplay();
      const pauseOnTransition = (event: { detail: { clipIndex: number } }) => {
        if (event.detail.clipIndex === 1) {
          element.pause();
        }
      };
      element.addEventListener(eventName, pauseOnTransition);
      const installed = sourceSet();
      media.dispatchEvent(new Event('ended'));
      await installed;
      media.dispatchEvent(new Event('loadstart'));
      loadedMetadata();
      await nativeAutoplay();
      expect(paused).toBe(true);
      expect(media.autoplay).toBe(true);
      element.removeEventListener(eventName, pauseOnTransition);
      await element.resume();
      expect(paused).toBe(false);
    },
  );

  it('honors Pause across a replacement playlist without changing native autoplay configuration', async () => {
    element.setAttribute('autoplay', '');
    player.autoplay(true);
    await start();
    await nativeAutoplay();
    element.pause();
    const installed = sourceSet();
    await element.play(sources);
    await installed;
    loadedMetadata();
    await nativeAutoplay();
    expect(paused).toBe(true);
    expect(media.autoplay).toBe(true);
    await element.resume();
    expect(paused).toBe(false);
  });

  it('uses public seek followed by public resume to play from an event without replacing the source again', async () => {
    await start();
    const installed = sourceSet();
    const seek = element.seek(15);
    await installed;
    loadedMetadata();
    await seek;
    expect(paused).toBe(true);
    const source = media.src;
    await element.resume();
    expect(paused).toBe(false);
    expect(media.src).toBe(source);
    expect(media.currentTime).toBe(5);
    expect(element.currentTime).toBe(15);
  });

  it('honors a later Pause after public resume during a pending cross-clip seek', async () => {
    await start();
    const installed = sourceSet();
    const seek = element.seek(15);
    const resume = element.resume();
    const cancelled = expect(resume).rejects.toMatchObject({ name: 'AbortError' });
    element.pause();
    await cancelled;
    await installed;
    media.dispatchEvent(new Event('loadstart'));
    loadedMetadata();
    await seek;
    expect(paused).toBe(true);
    expect(media.currentTime).toBe(5);
    expect(HTMLMediaElement.prototype.play).not.toHaveBeenCalled();
  });

  it('applies public resume intent to a pending cross-clip seek without a later Pause', async () => {
    await start();
    const installed = sourceSet();
    const seek = element.seek(15);
    const resume = element.resume();
    await installed;
    media.dispatchEvent(new Event('loadstart'));
    loadedMetadata();
    await resume;
    await seek;
    expect(paused).toBe(false);
    expect(media.currentTime).toBe(5);
    expect(element.currentTime).toBe(15);
  });

  it('rejects a deferred public resume when its initial media load fails', async () => {
    const installed = sourceSet();
    await element.play(sources);
    const resume = element.resume();
    const failure = expect(resume).rejects.toThrow('media request failed');
    await installed;
    const log = jest.spyOn(console, 'error').mockImplementation(() => {});
    player.error('media request failed');
    await failure;
    expect(log).toHaveBeenCalled();
    await expect(element.resume()).rejects.toThrow('media request failed');
  });

  it.each(['pause', 'replacement', 'dispose'] as const)(
    'rejects an unfinished public resume on %s',
    async (interruption) => {
      await start();
      jest.mocked(HTMLMediaElement.prototype.play).mockImplementationOnce(function (this: HTMLMediaElement) {
        paused = false;
        this.dispatchEvent(new Event('play'));
        return new Promise<void>(() => {});
      });
      const resume = element.resume();
      const cancelled = expect(resume).rejects.toMatchObject({ name: 'AbortError' });
      if (interruption === 'pause') {
        element.pause();
      } else if (interruption === 'replacement') {
        const installed = sourceSet();
        await element.play(sources);
        await installed;
        loadedMetadata();
      } else {
        await element.dispose();
      }
      await cancelled;
      if (interruption !== 'dispose') {
        await expect(element.resume()).resolves.toBeUndefined();
      }
    },
  );

  it('propagates a native autoplay rejection through public resume', async () => {
    await start();
    const failure = new DOMException('autoplay denied', 'NotAllowedError');
    jest.mocked(HTMLMediaElement.prototype.play).mockRejectedValueOnce(failure);
    await expect(element.resume()).rejects.toBe(failure);
    await expect(element.resume()).resolves.toBeUndefined();
  });

  it('ignores old-source metadata before asynchronous source installation and before new metadata is available', async () => {
    await start();
    media.currentTime = 3;
    const installed = sourceSet();
    const seeking = element.seek(15);
    let settled = false;
    void seeking.then(() => {
      settled = true;
    });
    expect(media.src).toBe(new URL(sources[0].src, document.baseURI).href);
    media.dispatchEvent(new Event('loadedmetadata'));
    await Promise.resolve();
    expect(settled).toBe(false);
    expect(media.currentTime).toBe(3);
    expect(element.currentTime).toBe(15);
    await installed;
    expect(media.src).toBe(new URL(sources[1].src, document.baseURI).href);
    media.dispatchEvent(new Event('loadedmetadata'));
    await Promise.resolve();
    expect(settled).toBe(false);
    loadedMetadata();
    await seeking;
    expect(media.currentTime).toBe(5);
    expect(element.currentTime).toBe(15);
    expect(element.currentClipIndex).toBe(1);
  });

  it('does not mistake metadata for a superseded source for the latest seek', async () => {
    await start();
    const first = element.seek(15);
    const cancelled = expect(first).rejects.toMatchObject({ name: 'AbortError' });
    const latestInstalled = new Promise<void>((resolve) => {
      const listener = (event: { src: string }) => {
        if (event.src === new URL(sources[2].src, document.baseURI).href) {
          player.off('sourceset', listener);
          resolve();
        } else {
          loadedMetadata();
        }
      };
      player.on('sourceset', listener);
    });
    const latest = element.seek(40);
    await cancelled;
    await latestInstalled;
    loadedMetadata();
    await latest;
    expect(media.currentTime).toBeCloseTo(10);
    expect(element.currentTime).toBe(40);
  });

  it('distinguishes new loads even when clips reuse the same source URL', async () => {
    await start(sources.map((source) => ({ ...source, src: sources[0].src })));
    const installed = sourceSet();
    const seek = element.seek(15);
    media.dispatchEvent(new Event('loadedmetadata'));
    await installed;
    loadedMetadata();
    await seek;
    expect(media.currentTime).toBe(5);
    expect(element.currentClipIndex).toBe(1);
  });

  it('ignores a superseded same-URL load even when its metadata arrives first', async () => {
    await start(sources.map((source) => ({ ...source, src: sources[0].src })));
    const first = element.seek(15);
    const cancelled = expect(first).rejects.toMatchObject({ name: 'AbortError' });
    let installations = 0;
    let settled = false;
    const installed = new Promise<void>((resolve) => {
      const listener = () => {
        installations++;
        if (installations === 1) {
          loadedMetadata();
        } else {
          player.off('sourceset', listener);
          resolve();
        }
      };
      player.on('sourceset', listener);
    });
    const latest = element.seek(40);
    void latest.then(() => {
      settled = true;
    });
    await cancelled;
    await installed;
    expect(settled).toBe(false);
    loadedMetadata();
    await latest;
    expect(media.currentTime).toBeCloseTo(10);
    expect(element.currentTime).toBe(40);
  });

  it.each([false, true])('preserves paused=%s without a control command during loading', async (initiallyPaused) => {
    await start();
    paused = initiallyPaused;
    const installed = sourceSet();
    const seek = element.seek(15);
    await installed;
    loadedMetadata();
    await seek;
    expect(paused).toBe(initiallyPaused);
  });

  it.each([false, true])(
    'honors the control-bar toggle from paused=%s during a pending seek',
    async (initiallyPaused) => {
      await start();
      const installed = sourceSet();
      const seek = element.seek(15);
      await installed;
      paused = initiallyPaused;
      const toggle = player.getChild('controlBar')?.getChild('playToggle');
      if (!toggle) {
        throw new Error('play toggle was not created');
      }
      const PlayToggleComponent = videojs.getComponent('PlayToggle') as typeof PlayToggle;
      PlayToggleComponent.prototype.handleClick.call(toggle);
      await Promise.resolve();
      loadedMetadata();
      await seek;
      expect(paused).toBe(!initiallyPaused);
    },
  );

  it('rejects an active load that failed earlier and permits seeking a different source', async () => {
    const installed = sourceSet();
    await element.play(sources);
    await installed;
    const log = jest.spyOn(console, 'error').mockImplementation(() => {});
    player.error('source unavailable');
    expect(log).toHaveBeenCalled();
    await expect(element.seek(5)).rejects.toThrow('source unavailable');
    const replacementInstalled = sourceSet();
    const seek = element.seek(15);
    await replacementInstalled;
    loadedMetadata();
    await seek;
    expect(element.currentTime).toBe(15);
  });

  it('rejects an unsupported source before it can queue an untagged selection error', async () => {
    jest.mocked(HTMLMediaElement.prototype.canPlayType).mockReturnValue('');
    await expect(element.play([{ ...sources[0], type: 'application/unsupported' }])).rejects.toThrow(
      'no compatible source was found for this media',
    );
    expect(player.error()).toBeNull();
  });

  it('keeps an existing playlist intact when a replacement initial source is unsupported', async () => {
    await start();
    jest.mocked(HTMLMediaElement.prototype.canPlayType).mockReturnValue('');
    await expect(element.play([{ ...sources[0], type: 'application/unsupported' }])).rejects.toThrow(
      'no compatible source was found for this media',
    );
    expect(element.duration).toBe(60);
    expect(element.currentClipIndex).toBe(0);
    expect(media.src).toBe(new URL(sources[0].src, document.baseURI).href);
    expect(player.error()).toBeNull();
  });

  it('ignores an old load error while the replacement source is still being installed', async () => {
    await start();
    const installed = sourceSet();
    const seek = element.seek(15);
    void seek.catch(() => {});
    const log = jest.spyOn(console, 'error').mockImplementation(() => {});
    player.error(2);
    expect(log).toHaveBeenCalled();
    await installed;
    loadedMetadata();
    await seek;
    expect(element.currentTime).toBe(15);
  });

  it('does not let a queued control Play override a later public Pause', async () => {
    await start();
    const installed = sourceSet();
    const seek = element.seek(15);
    const toggle = player.getChild('controlBar')?.getChild('playToggle');
    if (!toggle) {
      throw new Error('play toggle was not created');
    }
    const PlayToggleComponent = videojs.getComponent('PlayToggle') as typeof PlayToggle;
    PlayToggleComponent.prototype.handleClick.call(toggle);
    element.pause();
    await installed;
    media.dispatchEvent(new Event('loadstart'));
    expect(paused).toBe(true);
    loadedMetadata();
    await seek;
    expect(paused).toBe(true);
  });

  it('rejects cancelled underlying Play promises and allows a later Play command', async () => {
    await start();
    const installed = sourceSet();
    const seek = element.seek(15);
    const playing = player.play();
    const cancelled = expect(playing).rejects.toMatchObject({ name: 'AbortError' });
    element.pause();
    await cancelled;
    await installed;
    media.dispatchEvent(new Event('loadstart'));
    expect(paused).toBe(true);
    loadedMetadata();
    await seek;
    await player.play();
    expect(paused).toBe(false);
  });

  it('retains Pause intent when a failed superseding seek clears pending work', async () => {
    jest.mocked(HTMLMediaElement.prototype.canPlayType).mockImplementation((type) => {
      return type === 'application/unsupported' ? '' : 'probably';
    });
    await start([sources[0], sources[1], { ...sources[2], type: 'application/unsupported' }]);
    const installed = sourceSet();
    const first = element.seek(15);
    const aborted = expect(first).rejects.toMatchObject({ name: 'AbortError' });
    const playing = player.play();
    const cancelled = expect(playing).rejects.toMatchObject({ name: 'AbortError' });
    element.pause();
    await expect(element.seek(40)).rejects.toThrow('no compatible source was found for this media');
    await aborted;
    await cancelled;
    await installed;
    media.dispatchEvent(new Event('loadstart'));
    loadedMetadata();
    expect(paused).toBe(true);
    expect(HTMLMediaElement.prototype.play).not.toHaveBeenCalled();
  });

  it('retains Play intent for a recovery seek after a source-reset pause and failed supersession', async () => {
    jest.mocked(HTMLMediaElement.prototype.canPlayType).mockImplementation((type) => {
      return type === 'application/unsupported' ? '' : 'probably';
    });
    await start([
      sources[0],
      sources[1],
      { ...sources[2], type: 'application/unsupported' },
      { ...sources[0], src: 'fourth.webm' },
    ]);
    await player.play();
    const installed = sourceSet();
    const first = element.seek(15);
    const aborted = expect(first).rejects.toMatchObject({ name: 'AbortError' });
    await installed;
    expect(paused).toBe(true);
    await expect(element.seek(40)).rejects.toThrow('no compatible source was found for this media');
    await aborted;
    const recoveryInstalled = sourceSet();
    const recovered = element.seek(65);
    await recoveryInstalled;
    loadedMetadata();
    await recovered;
    expect(element.currentTime).toBe(65);
    expect(paused).toBe(false);
  });

  it('honors a queued Play when seeking the initial clip before source installation', async () => {
    const installed = sourceSet();
    await element.play(sources);
    const playing = player.play();
    const seeking = element.seek(5);
    await installed;
    loadedMetadata();
    await seeking;
    await playing;
    expect(element.currentTime).toBe(5);
    expect(paused).toBe(false);
  });

  it('retains Pause intent across playlist replacement until a new Play request', async () => {
    await start();
    const first = element.seek(15);
    const aborted = expect(first).rejects.toMatchObject({ name: 'AbortError' });
    const playing = player.play();
    const cancelled = expect(playing).rejects.toMatchObject({ name: 'AbortError' });
    element.pause();
    const replacementInstalled = new Promise<void>((resolve) => {
      const listener = (event: { src: string }) => {
        if (event.src === new URL(sources[0].src, document.baseURI).href) {
          player.off('sourceset', listener);
          resolve();
        }
      };
      player.on('sourceset', listener);
    });
    await element.play(sources);
    await aborted;
    await cancelled;
    await replacementInstalled;
    media.dispatchEvent(new Event('loadstart'));
    loadedMetadata();
    expect(paused).toBe(true);
    expect(HTMLMediaElement.prototype.play).not.toHaveBeenCalled();
    await player.play();
    expect(paused).toBe(false);
  });

  it('settles an applied seek against the latest Play after Pause cancels its first resume', async () => {
    await start();
    paused = false;
    jest.mocked(HTMLMediaElement.prototype.play).mockImplementationOnce(function (this: HTMLMediaElement) {
      paused = false;
      this.dispatchEvent(new Event('play'));
      return new Promise<void>(() => {});
    });
    const installed = sourceSet();
    const seek = element.seek(15);
    await installed;
    loadedMetadata();
    element.pause();
    await player.play();
    await expect(seek).resolves.toBeUndefined();
    expect(paused).toBe(false);
    expect(media.currentTime).toBe(5);
    expect(element.currentTime).toBe(15);
  });

  it('restores decorated player methods on playlist replacement and disposal', async () => {
    const originalPlay = player.play;
    const originalPause = player.pause;
    await start();
    expect(player.play).not.toBe(originalPlay);
    expect(player.pause).not.toBe(originalPause);
    const installed = sourceSet();
    await element.play(sources);
    await installed;
    loadedMetadata();
    await player.play();
    expect(paused).toBe(false);
    await element.dispose();
    expect(player.play).toBe(originalPlay);
    expect(player.pause).toBe(originalPause);
  });

  it('does not let a delayed unsupported-source error poison a supported replacement', async () => {
    await start();
    jest.mocked(HTMLMediaElement.prototype.canPlayType).mockImplementation((type) => {
      return type === 'application/unsupported' ? '' : 'probably';
    });
    await element.play([sources[0], { ...sources[1], type: 'application/unsupported' }, sources[2]]);
    const initialInstalled = sourceSet();
    await initialInstalled;
    loadedMetadata();
    const failed = element.seek(15);
    const failure = expect(failed).rejects.toThrow();
    const installed = sourceSet();
    const replacement = element.seek(40);
    const replacementResult = replacement.then(
      () => undefined,
      (error: Error) => error,
    );
    const log = jest.spyOn(console, 'error').mockImplementation(() => {});
    await installed;
    await new Promise<void>((resolve) => setTimeout(resolve, 10));
    media.dispatchEvent(new Event('loadstart'));
    loadedMetadata();
    await failure;
    expect(await replacementResult).toBeUndefined();
    await expect(element.seek(40)).resolves.toBeUndefined();
    expect(element.currentTime).toBe(40);
    log.mockRestore();
  });

  it('reports an unsupported automatic successor and permits explicit recovery to another clip', async () => {
    jest.mocked(HTMLMediaElement.prototype.canPlayType).mockImplementation((type) => {
      return type === 'application/unsupported' ? '' : 'probably';
    });
    await start([sources[0], { ...sources[1], type: 'application/unsupported' }, sources[2]]);
    const log = jest.spyOn(console, 'error').mockImplementation(() => {});
    media.dispatchEvent(new Event('ended'));
    expect(log).toHaveBeenCalledWith('Playback failed:', expect.any(Error));
    expect(element.currentClipIndex).toBe(0);
    const installed = sourceSet();
    const recovered = element.seek(40);
    await installed;
    loadedMetadata();
    await recovered;
    expect(element.currentTime).toBe(40);
  });

  it('types and delivers descendant native events separately from component clock events in capture mode', async () => {
    await start();
    const captured: Event[] = [];
    const custom: CustomEvent<{ currentTime: number; clipIndex: number }>[] = [];
    element.addEventListener('timeupdate', (event) => {
      custom.push(event);
      expect(event.detail.clipIndex).toBe(0);
    });
    element.addEventListener(
      'timeupdate',
      (event) => {
        captured.push(event);
        // @ts-expect-error Capturing listeners can receive a native Event without detail.
        const detail = event.detail;
        if (event instanceof CustomEvent) {
          expect(detail).toEqual({ currentTime: 3, clipIndex: 0 });
        } else {
          expect(detail).toBeUndefined();
        }
      },
      { capture: true },
    );
    media.currentTime = 3;
    media.dispatchEvent(new Event('timeupdate'));
    expect(captured).toHaveLength(2);
    expect(captured.filter((event) => !(event instanceof CustomEvent))).toHaveLength(1);
    expect(custom).toHaveLength(1);
  });

  it('keeps native event typing for boolean and runtime-selected capture options', () => {
    function listen(options: boolean | AddEventListenerOptions) {
      element.addEventListener(
        'timeupdate',
        (event) => {
          // @ts-expect-error Runtime-selected capture options cannot guarantee a CustomEvent.
          void event.detail;
        },
        options,
      );
    }
    element.addEventListener(
      'timeupdate',
      (event) => {
        // @ts-expect-error Boolean true enables capture of native events.
        void event.detail;
      },
      true,
    );
    listen({ capture: true });
  });

  it.each(['', ' ', '\t'])('rejects invalid initial URL %j without creating a playlist', async (src) => {
    await expect(element.play([{ ...sources[0], src }])).rejects.toThrow('source URL must be a nonempty string');
    expect(element.duration).toBe(0);
    expect(element.currentClipIndex).toBe(-1);
    expect(player.error()).toBeNull();
    await expect(element.seek(5)).resolves.toBeUndefined();
  });

  it.each(['', ' ', '\t'])('preserves playback when a replacement initial URL is %j', async (src) => {
    await start();
    await player.play();
    const currentSource = media.src;
    await expect(element.play([{ ...sources[0], src }])).rejects.toThrow('source URL must be a nonempty string');
    expect(element.duration).toBe(60);
    expect(element.currentClipIndex).toBe(0);
    expect(media.src).toBe(currentSource);
    expect(paused).toBe(false);
    expect(player.error()).toBeNull();
  });

  it.each(['', ' ', '\t'])('rejects seeking to clip URL %j without leaving its load pending', async (src) => {
    await start([sources[0], { ...sources[1], src }, sources[2]]);
    await expect(element.seek(15)).rejects.toThrow('source URL must be a nonempty string');
    expect(element.currentClipIndex).toBe(0);
    expect(media.src).toBe(new URL(sources[0].src, document.baseURI).href);
    expect(player.error()).toBeNull();
    await expect(element.seek(5)).resolves.toBeUndefined();
    expect(element.currentTime).toBe(5);
  });
});
