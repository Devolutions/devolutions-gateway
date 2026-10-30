import Player from 'video.js/dist/types/player';
import { observePlayer, playbackIntent, settlePlayback } from './player-observer';
import { Percentage, Status, VideoTime } from './util';
import type { SourceMetadata } from './video-player/player';
import type { SingleVideoSeekBar } from './video-player/single-video-seek-bar';

export function playableSource(player: Player, metadata: SourceMetadata) {
  if (typeof metadata.src !== 'string' || metadata.src.trim().length === 0) {
    throw new RangeError('source URL must be a nonempty string');
  }
  const source = { src: metadata.src, type: metadata.type };
  if (!player.selectSource([source])) {
    throw new Error('no compatible source was found for this media');
  }
  return source;
}

export class ProgressManager {
  handles: ProgressManagerHandle[] = [];
  readonly duration: number;
  player: Player;
  private currentIndex = -1;
  private sourceInstalled = false;
  private sourceLoadId = Symbol();
  private installingSourceLoadId?: symbol;
  private metadataLoaded = false;
  private loadError?: Error;
  private disposed = false;
  private readonly removePlayerObserver: () => void;
  private readonly pendingResume = new Set<(error: Error) => void>();
  private pendingSeek?: {
    offset: number;
    resume: boolean;
    cancel: (error: Error) => void;
  };

  constructor(
    player: Player,
    playList: SourceMetadata[],
    private readonly onTimeUpdate?: () => void,
    private readonly onClipChange?: () => void,
  ) {
    this.player = player;
    let duration = 0;
    this.handles = playList.map((source, index) => {
      const handle = new ProgressManagerHandle(this, source, index, duration);
      duration += handle.souce.duration;
      return handle;
    });
    this.duration = duration;
    this.player.on(['play', 'durationchange', 'timeupdate'], this.updateCurrentHandle);
    this.player.on('loadedmetadata', this.handleLoadedMetadata);
    this.player.on('sourceset', this.handleSourceSet);
    this.player.on('error', this.handleError);
    this.removePlayerObserver = observePlayer(this.player, {
      playbackCommand: (playing) => {
        if (this.pendingSeek) {
          this.pendingSeek.resume = playing;
        }
      },
      sourceChange: (source) => {
        this.installingSourceLoadId = source.multiVideoPlayerLoadId;
        this.sourceInstalled = false;
        this.metadataLoaded = false;
      },
    });
    this.player.on('ended', this.handleEnded);
  }

  get currentTime() {
    const handle = this.currentPlayingHandle();
    if (!handle) {
      return 0;
    }
    const offset = this.pendingSeek?.offset ?? (this.metadataLoaded ? this.clipTime(handle) : 0);
    return handle.startTime + offset;
  }

  start() {
    const handle = this.handles[0];
    if (handle) {
      this.setSource(handle);
    }
  }

  forEachHandle(acceptCallback: (worker: ProgressManagerHandle) => void) {
    for (const worker of this.handles) {
      acceptCallback(worker);
    }
  }

  seek(seconds: number): Promise<void> {
    if (!Number.isFinite(seconds)) {
      return Promise.reject(new RangeError('seek time must be finite'));
    }
    const time = Math.max(0, Math.min(seconds, this.duration));
    const handle =
      this.handles.find((handle) => time < handle.startTime + handle.souce.duration) ??
      this.handles[this.handles.length - 1];
    if (!handle) {
      return Promise.resolve();
    }
    const offset = Math.max(0, Math.min(time - handle.startTime, handle.souce.duration));
    const percentage =
      handle.souce.duration === 0 ? Percentage.zero() : Percentage.devidedBy(offset, handle.souce.duration);
    return this.userSeek(handle, percentage);
  }

  userSeek(seekHandle: ProgressManagerHandle, percentage: Percentage): Promise<void> {
    if (this.disposed) {
      return Promise.reject(new DOMException('player is disposed', 'InvalidStateError'));
    }
    if (seekHandle === this.currentPlayingHandle() && this.loadError) {
      return Promise.reject(this.loadError);
    }

    const resume = this.pendingSeek?.resume ?? playbackIntent(this.player);
    this.pendingSeek?.cancel(new DOMException('seek superseded', 'AbortError'));
    const offset = seekHandle.souce.duration * percentage.toDecimal();

    return new Promise<void>((resolve, reject) => {
      const finish = (error?: Error) => {
        this.player.off('loadedmetadata', apply);
        if (this.pendingSeek?.cancel !== finish) {
          return;
        }
        this.pendingSeek = undefined;
        if (error) {
          reject(error);
        } else {
          resolve();
        }
      };
      const apply = () => {
        if (this.pendingSeek?.cancel !== finish || !this.hasCurrentMetadata()) {
          return;
        }
        this.player.off('loadedmetadata', apply);
        try {
          this.player.currentTime(offset);
          this.updateProgress(seekHandle, percentage);
          this.onTimeUpdate?.();
          if (this.pendingSeek?.cancel !== finish) {
            return;
          }
          if (!this.pendingSeek.resume) {
            this.player.pause();
          }
          const playing = this.pendingSeek.resume ? this.player.play() : undefined;
          settlePlayback(this.player, playing).then(
            () => finish(),
            (error: unknown) => finish(error instanceof Error ? error : new Error(String(error))),
          );
        } catch (error) {
          finish(error instanceof Error ? error : new Error(String(error)));
        }
      };

      this.pendingSeek = { offset, resume, cancel: finish };
      this.player.on('loadedmetadata', apply);
      try {
        if (seekHandle !== this.currentPlayingHandle()) {
          this.setSource(seekHandle);
        }
        if (this.pendingSeek?.cancel !== finish) {
          return;
        }
        this.updateProgress(seekHandle, percentage);
        if (this.metadataLoaded) {
          apply();
        }
      } catch (error) {
        finish(error instanceof Error ? error : new Error(String(error)));
      }
    });
  }

  pause() {
    if (this.pendingSeek) {
      this.pendingSeek.resume = false;
    }
  }

  async resume(): Promise<void> {
    if (this.disposed) {
      throw new DOMException('player is disposed', 'InvalidStateError');
    }
    if (!this.currentPlayingHandle()) {
      return;
    }
    if (this.loadError) {
      throw this.loadError;
    }
    let fail!: (error: Error) => void;
    const failed = new Promise<never>((_resolve, reject) => {
      fail = reject;
    });
    this.pendingResume.add(fail);
    try {
      await Promise.race([this.player.play(), failed]);
    } finally {
      this.pendingResume.delete(fail);
    }
  }

  dispose() {
    this.disposed = true;
    this.pendingSeek?.cancel(new DOMException('playback interrupted', 'AbortError'));
    for (const fail of this.pendingResume) {
      fail(new DOMException('playback interrupted', 'AbortError'));
    }
    this.pendingResume.clear();
    this.player.off(['play', 'durationchange', 'timeupdate'], this.updateCurrentHandle);
    this.player.off('loadedmetadata', this.handleLoadedMetadata);
    this.player.off('sourceset', this.handleSourceSet);
    this.player.off('error', this.handleError);
    this.removePlayerObserver();
    this.player.off('ended', this.handleEnded);
  }

  getVideoDurationPercentage(worker: ProgressManagerHandle) {
    return this.duration === 0 ? 0 : Math.round((worker.souce.duration / this.duration) * 100);
  }

  currentPlayingHandle() {
    return this.handles[this.currentIndex];
  }

  private clipTime(handle: ProgressManagerHandle) {
    const time = this.player.currentTime() ?? 0;
    return Number.isFinite(time) ? Math.max(0, Math.min(time, handle.souce.duration)) : 0;
  }

  private setSource(handle: ProgressManagerHandle, autoplay = false) {
    const source = playableSource(this.player, handle.souce);
    const changed = this.currentIndex !== handle.index;
    this.currentIndex = handle.index;
    this.sourceInstalled = false;
    this.sourceLoadId = Symbol();
    this.metadataLoaded = false;
    this.loadError = undefined;
    this.updateProgress(handle, Percentage.zero());
    this.player.src({ ...source, multiVideoPlayerLoadId: this.sourceLoadId });
    if (autoplay) {
      // Queue playback before publishing callbacks so a newer Pause can cancel it.
      this.player.play()?.catch((error: unknown) => {
        if (!(error instanceof DOMException && error.name === 'AbortError')) {
          console.error('Playback failed:', error);
        }
      });
    }
    const loadId = this.sourceLoadId;
    if (changed) {
      this.onClipChange?.();
    }
    if (this.disposed || this.sourceLoadId !== loadId) {
      return;
    }
    this.onTimeUpdate?.();
  }

  private updateProgress(current: ProgressManagerHandle, percentage: Percentage) {
    for (const handle of this.handles) {
      if (handle.index < current.index) {
        handle.status = { status: 'ended' };
      } else if (handle === current) {
        handle.status = { status: 'playing', percentage };
      } else {
        handle.status = { status: 'NotStarted' };
      }
    }
  }

  private updateCurrentHandle = () => {
    const handle = this.currentPlayingHandle();
    if (!handle || !this.metadataLoaded || !this.hasCurrentMetadata() || this.pendingSeek) {
      return;
    }
    handle.status = {
      status: 'playing',
      percentage:
        handle.souce.duration === 0
          ? Percentage.zero()
          : Percentage.devidedBy(this.clipTime(handle), handle.souce.duration),
    };
    this.onTimeUpdate?.();
  };

  private handleLoadedMetadata = () => {
    if (!this.hasCurrentMetadata()) {
      return;
    }
    this.metadataLoaded = true;
    this.updateCurrentHandle();
  };

  private hasCurrentMetadata() {
    return this.sourceInstalled && this.player.readyState() >= 1;
  }

  private handleSourceSet = (event: { src?: string }) => {
    const handle = this.currentPlayingHandle();
    this.sourceInstalled =
      !!handle &&
      !!event.src &&
      this.installingSourceLoadId === this.sourceLoadId &&
      new URL(event.src, document.baseURI).href === new URL(handle.souce.src, document.baseURI).href;
    this.metadataLoaded = false;
  };

  private handleError = () => {
    const error = this.player.error();
    if (this.installingSourceLoadId !== this.sourceLoadId || (!this.sourceInstalled && error?.code !== 4)) {
      return;
    }
    this.loadError = new Error(error?.message || 'video source failed to load');
    this.pendingSeek?.cancel(this.loadError);
    for (const fail of this.pendingResume) {
      fail(this.loadError);
    }
  };

  private handleEnded = () => {
    if (this.pendingSeek || !this.metadataLoaded || !this.hasCurrentMetadata()) {
      return;
    }
    const handle = this.currentPlayingHandle();
    if (handle) {
      handle.status = { status: 'ended' };
      const next = this.handles[handle.index + 1];
      try {
        this.setSource(next ?? this.handles[0], !!next);
      } catch (error) {
        console.error('Playback failed:', error);
      }
    }
  };
}

export class ProgressManagerHandle {
  readonly souce: Readonly<SourceMetadata>;
  index: number;
  manager: ProgressManager;
  component: SingleVideoSeekBar | undefined;
  private _status: Status = { status: 'NotStarted' };
  private statusUpdateCallback: ((status: Status) => void) | undefined;

  constructor(
    manager: ProgressManager,
    souce: SourceMetadata,
    index: number,
    readonly startTime: number,
  ) {
    this.souce = { src: souce.src, type: souce.type, duration: souce.duration };
    this.index = index;
    this.manager = manager;
  }

  set status(value: Status) {
    this.statusUpdateCallback?.(value);
    this._status = value;
  }

  get status() {
    return this._status;
  }

  register(component: SingleVideoSeekBar) {
    this.component = component;
  }

  onStatusUpdate(callback: (status: Status) => void) {
    this.statusUpdateCallback = callback;
  }

  // For the width of each single video seek bar
  getPercentageLength() {
    return this.manager.getVideoDurationPercentage(this);
  }

  userSeek(percentage: Percentage) {
    return this.manager.userSeek(this, percentage);
  }

  percentageToTime(percentage: Percentage) {
    return new VideoTime(this.startTime + this.souce.duration * percentage.toDecimal());
  }
}
