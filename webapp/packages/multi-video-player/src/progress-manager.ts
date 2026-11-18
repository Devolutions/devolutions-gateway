import Player from 'video.js/dist/types/player';
import { finishPlayback, observePlayer, playbackIntent, settlePlayback } from './player-observer';
import { Percentage, Status, VideoTime } from './util';
import type { PlaybackObservation, SourceMetadata } from './video-player/player';
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
  observation?: PlaybackObservation;
  private completed = false;
  private holdEndpoint = false;
  private tail?: { time: number; rate: number; startedAt?: number; timer?: ReturnType<typeof setTimeout> };
  private autoplayLoadId?: symbol;
  private playbackCommandId = 0;
  private pauseRequested = false;
  private readonly removePlayerObserver: () => void;
  private readonly pendingResume = new Set<(error: Error) => void>();
  private pendingSeek?: {
    resume: boolean;
    cancel: (error?: Error) => void;
    applied: boolean;
    seekStarted: boolean;
    seeked: boolean;
    mayHaveAdvanced: boolean;
    observedSeekTimeUpdate: boolean;
    ended: boolean;
    target: number;
    offset: number;
    tail: boolean;
    loadId: symbol;
  };

  constructor(
    player: Player,
    playList: SourceMetadata[],
    private readonly onTimeUpdate?: (observation: PlaybackObservation) => void,
    private readonly onClipChange?: (observation: PlaybackObservation) => void,
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
    this.player.on(['seeking', 'seeked', 'loadeddata', 'canplay'], this.handleSeekProgress);
    this.player.on('sourceset', this.handleSourceSet);
    this.player.on('error', this.handleError);
    this.player.on('ratechange', this.handleRateChange);
    this.removePlayerObserver = observePlayer(this.player, {
      isInternalPause: (nativeEnded) => !this.pauseRequested && nativeEnded,
      playbackCommand: (playing) => {
        this.playbackCommandId++;
        this.autoplayLoadId = undefined;
        const wasTailing = this.tail?.startedAt !== undefined;
        if (playing) {
          if (this.loadError) {
            this.pauseRequested = true;
            finishPlayback(this.player);
          } else {
            this.pauseRequested = false;
          }
        } else {
          this.pauseRequested = true;
          this.stopTail();
        }
        if (this.pendingSeek) {
          this.pendingSeek.resume = playing;
          if (playing && this.pendingSeek.applied) {
            this.pendingSeek.mayHaveAdvanced = true;
          }
        }
        if (!playing) {
          const error = new DOMException('playback interrupted', 'AbortError');
          for (const fail of this.pendingResume) {
            fail(error);
          }
        }
        if (!playing && wasTailing) {
          const handle = this.currentPlayingHandle();
          if (handle) {
            this.publishObservation(handle, 'ready');
          }
          if (this.tail && this.tail.startedAt === undefined && !this.disposed) {
            this.player.trigger('pause');
          }
        }
      },
      shouldHoldPlay: () => this.holdEndpoint,
      interceptPlay: () => {
        if (this.loadError) {
          return Promise.reject(this.loadError);
        }
        if (this.completed) {
          return this.resume();
        }
        if (this.tail) {
          this.startTail();
          return Promise.resolve();
        }
        if (this.pendingSeek?.tail) {
          return Promise.resolve();
        }
        return undefined;
      },
      paused: () => (this.tail ? this.tail.startedAt === undefined : undefined),
      ended: () => (this.tail ? this.completed : undefined),
      sourceChange: (source) => {
        this.installingSourceLoadId = source.multiVideoPlayerLoadId;
        this.sourceInstalled = false;
        this.metadataLoaded = false;
      },
    });
    this.player.on('ended', this.handleEnded);
  }

  get currentTime() {
    return this.observation?.currentTime ?? 0;
  }

  get playing() {
    if (this.tail) {
      return this.tail.startedAt !== undefined;
    }
    return (
      this.observation?.readiness === 'ready' && !this.player.paused() && !this.player.ended() && !this.player.seeking()
    );
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

    const resume = this.pendingSeek?.resume ?? (!this.completed && playbackIntent(this.player));
    this.pendingSeek?.cancel(new DOMException('seek superseded', 'AbortError'));
    const offset = seekHandle.souce.duration * percentage.toDecimal();
    const previousLoadId = this.sourceLoadId;
    const previousObservation = this.observation;
    const wasCompleted = this.completed;
    const heldEndpoint = this.holdEndpoint;
    const tailWasPlaying = this.tail?.startedAt !== undefined;
    this.stopTail();
    const previousTail = this.tail;
    this.completed = false;
    this.holdEndpoint = false;
    this.tail = undefined;
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
          const duration = this.player.duration();
          const target =
            typeof duration === 'number' && Number.isFinite(duration) ? Math.min(offset, duration) : offset;
          // An ended element may not have presented its final frame, so a completed recording always seeks.
          const sameTime =
            !wasCompleted && !previousTail && Math.abs((this.player.currentTime() ?? 0) - target) < 0.000001;
          this.pendingSeek.target = target;
          this.pendingSeek.tail =
            typeof duration === 'number' && target >= duration && duration < seekHandle.souce.duration;
          this.pendingSeek.loadId = this.sourceLoadId;
          this.pendingSeek.applied = true;
          this.pendingSeek.seekStarted = false;
          this.pendingSeek.seeked = sameTime && !this.player.seeking();
          this.pendingSeek.mayHaveAdvanced = !this.player.paused();
          this.pendingSeek.observedSeekTimeUpdate = false;
          if (!sameTime || this.player.seeking()) {
            this.player.currentTime(target);
          }
          if (!this.pendingSeek.resume && (!wasCompleted || !this.player.paused())) {
            this.player.pause();
          }
          const playing = this.pendingSeek.resume ? this.player.play() : undefined;
          void settlePlayback(this.player, playing).catch((error: unknown) =>
            finish(error instanceof Error ? error : new Error(String(error))),
          );
          this.handleSeekProgress();
        } catch (error) {
          finish(error instanceof Error ? error : new Error(String(error)));
        }
      };

      this.pendingSeek = {
        resume,
        cancel: finish,
        applied: false,
        seekStarted: false,
        seeked: false,
        mayHaveAdvanced: false,
        observedSeekTimeUpdate: false,
        ended: false,
        target: 0,
        offset,
        tail: false,
        loadId: this.sourceLoadId,
      };
      this.player.on('loadedmetadata', apply);
      if (this.observation) {
        this.observation = { ...this.observation, readiness: 'seeking' };
        this.onTimeUpdate?.(this.observation);
      }
      if (this.pendingSeek?.cancel !== finish) {
        return;
      }
      try {
        if (seekHandle !== this.currentPlayingHandle()) {
          this.setSource(seekHandle);
        }
        if (this.pendingSeek?.cancel !== finish) {
          return;
        }
        if (this.metadataLoaded) {
          apply();
        }
      } catch (error) {
        const failure = error instanceof Error ? error : new Error(String(error));
        if (this.sourceLoadId === previousLoadId && this.pendingSeek?.cancel === finish) {
          this.completed = wasCompleted;
          this.holdEndpoint = heldEndpoint;
          this.tail = previousTail;
          finish(failure);
          if (previousObservation) {
            this.observation = previousObservation;
            this.onTimeUpdate?.(previousObservation);
          }
          if (tailWasPlaying && !this.pauseRequested && !this.pendingSeek && !this.disposed) {
            this.startTail();
          }
        } else {
          finish(failure);
        }
      }
    });
  }

  pause() {
    this.pauseRequested = true;
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
    const commandId = this.playbackCommandId;
    const restart = this.completed ? this.seek(0) : undefined;
    if (restart && this.playbackCommandId !== commandId && !playbackIntent(this.player)) {
      void restart.catch(() => {});
      throw new DOMException('playback interrupted', 'AbortError');
    }
    let fail!: (error: Error) => void;
    const failed = new Promise<never>((_resolve, reject) => {
      fail = reject;
    });
    this.pendingResume.add(fail);
    try {
      const playing = settlePlayback(this.player, this.player.play());
      await Promise.race([Promise.all(restart ? [playing, restart] : [playing]), failed]);
    } finally {
      this.pendingResume.delete(fail);
    }
  }

  dispose() {
    this.disposed = true;
    this.stopTail();
    this.pendingSeek?.cancel(new DOMException('playback interrupted', 'AbortError'));
    for (const fail of this.pendingResume) {
      fail(new DOMException('playback interrupted', 'AbortError'));
    }
    this.pendingResume.clear();
    this.player.off(['play', 'durationchange', 'timeupdate'], this.updateCurrentHandle);
    this.player.off('loadedmetadata', this.handleLoadedMetadata);
    this.player.off(['seeking', 'seeked', 'loadeddata', 'canplay'], this.handleSeekProgress);
    this.player.off('sourceset', this.handleSourceSet);
    this.player.off('error', this.handleError);
    this.player.off('ratechange', this.handleRateChange);
    this.removePlayerObserver();
    this.player.off('ended', this.handleEnded);
  }

  getVideoDurationPercentage(worker: ProgressManagerHandle) {
    return this.duration === 0 ? 0 : Math.round((worker.souce.duration / this.duration) * 100);
  }

  currentPlayingHandle() {
    return this.handles[this.currentIndex];
  }

  private clipTime() {
    const time = this.player.currentTime() ?? 0;
    return Number.isFinite(time) ? Math.max(0, time) : 0;
  }

  private setSource(handle: ProgressManagerHandle, autoplay = false) {
    const source = playableSource(this.player, handle.souce);
    this.stopTail();
    this.tail = undefined;
    this.currentIndex = handle.index;
    this.sourceInstalled = false;
    this.sourceLoadId = Symbol();
    this.metadataLoaded = false;
    this.loadError = undefined;
    this.autoplayLoadId = autoplay ? this.sourceLoadId : undefined;
    const loadId = this.sourceLoadId;
    if (this.observation) {
      this.observation = { ...this.observation, readiness: 'loading' };
      this.onTimeUpdate?.(this.observation);
    }
    if (this.disposed || this.sourceLoadId !== loadId) {
      return;
    }
    this.player.src({ ...source, multiVideoPlayerLoadId: this.sourceLoadId });
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

  private updateCurrentHandle = (event?: { type?: string }) => {
    const handle = this.currentPlayingHandle();
    if (!handle || !this.metadataLoaded || !this.hasCurrentMetadata()) {
      return;
    }
    const pending = this.pendingSeek;
    if (pending) {
      if (
        event?.type === 'timeupdate' &&
        pending.applied &&
        pending.seekStarted &&
        pending.loadId === this.sourceLoadId &&
        !this.player.seeking()
      ) {
        const tolerance = pending.target === 0 ? 0.01 : 0.000001;
        if ((this.player.currentTime() ?? 0) >= pending.target - tolerance) {
          pending.observedSeekTimeUpdate = true;
        }
      }
      return;
    }
    this.publishObservation(
      handle,
      this.completed
        ? 'ended'
        : this.player.seeking()
          ? 'seeking'
          : this.player.readyState() >= 2
            ? 'ready'
            : 'loading',
    );
  };

  private handleLoadedMetadata = () => {
    if (!this.hasCurrentMetadata()) {
      return;
    }
    this.metadataLoaded = true;
    const handle = this.currentPlayingHandle();
    if (!handle) {
      return;
    }
    const changed = this.observation?.clipIndex !== handle.index;
    const readiness = this.pendingSeek ? 'seeking' : this.player.readyState() >= 2 ? 'ready' : 'loading';
    this.publishObservation(handle, readiness, changed);
    if (this.autoplayLoadId === this.sourceLoadId && !this.disposed) {
      this.autoplayLoadId = undefined;
      this.player.play()?.catch((error: unknown) => {
        if (!(error instanceof DOMException && error.name === 'AbortError')) {
          console.error('Playback failed:', error);
        }
      });
    }
  };

  private publishObservation(
    handle: ProgressManagerHandle,
    readiness: PlaybackObservation['readiness'],
    changed = false,
  ) {
    const localTime = this.clipTime();
    const duration = this.player.duration();
    const observation: PlaybackObservation = {
      clipIndex: handle.index,
      localTime,
      ...(typeof duration === 'number' && Number.isFinite(duration) ? { clipDuration: duration } : {}),
      currentTime: handle.startTime + Math.min(this.tail?.time ?? localTime, handle.souce.duration),
      readiness,
    };
    const previousIndex = this.observation?.clipIndex;
    this.observation = observation;
    const percentage =
      handle.souce.duration === 0
        ? Percentage.zero()
        : Percentage.devidedBy(Math.min(this.tail?.time ?? localTime, handle.souce.duration), handle.souce.duration);
    if (previousIndex !== handle.index) {
      this.updateProgress(handle, percentage);
    } else {
      handle.status = readiness === 'ended' ? { status: 'ended' } : { status: 'playing', percentage };
    }
    if (changed) {
      this.onClipChange?.(observation);
    }
    if (!this.disposed && this.observation === observation) {
      this.onTimeUpdate?.(observation);
    }
  }

  private handleSeekProgress = (event?: { type?: string }) => {
    const pending = this.pendingSeek;
    if (!pending) {
      this.updateCurrentHandle();
      return;
    }
    if (!pending.applied || pending.loadId !== this.sourceLoadId || !this.hasCurrentMetadata()) {
      return;
    }
    if (event?.type === 'seeking') {
      pending.seekStarted = true;
      return;
    }
    // A completed seek queues timeupdate before seeked; playback may advance between them.
    // Some WebM files report their first sample a few milliseconds after zero.
    const time = this.player.currentTime() ?? 0;
    const tolerance = pending.target === 0 ? 0.01 : 0.000001;
    if (
      event?.type === 'seeked' &&
      pending.seekStarted &&
      !this.player.seeking() &&
      (Math.abs(time - pending.target) <= tolerance ||
        (pending.mayHaveAdvanced && pending.observedSeekTimeUpdate && time >= pending.target - tolerance))
    ) {
      pending.seeked = true;
    }
    if (!pending.seeked || this.player.readyState() < 2) {
      return;
    }
    void settlePlayback(this.player).then(
      () => {
        if (this.pendingSeek !== pending || pending.loadId !== this.sourceLoadId) {
          return;
        }
        const handle = this.currentPlayingHandle();
        if (!handle) {
          return;
        }
        const duration = this.player.duration();
        const endpoint = Math.min(
          handle.souce.duration,
          typeof duration === 'number' && Number.isFinite(duration) ? duration : handle.souce.duration,
        );
        this.tail =
          pending.target >= endpoint && endpoint < handle.souce.duration
            ? { time: pending.offset, rate: this.player.playbackRate() ?? 1 }
            : undefined;
        this.holdEndpoint = !pending.resume && pending.offset >= handle.souce.duration;
        this.publishObservation(handle, 'ready');
        if (this.pendingSeek !== pending) {
          return;
        }
        const ended = pending.ended && pending.resume && this.player.ended();
        pending.cancel();
        if (
          this.tail &&
          pending.resume &&
          !this.disposed &&
          this.sourceLoadId === pending.loadId &&
          !this.pendingSeek
        ) {
          this.startTail();
        }
        if (ended && !this.disposed && this.sourceLoadId === pending.loadId && !this.pendingSeek) {
          this.handleEnded();
        }
      },
      (error: unknown) => pending.cancel(error instanceof Error ? error : new Error(String(error))),
    );
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
    this.stopTail();
    this.pendingSeek?.cancel(this.loadError);
    for (const fail of this.pendingResume) {
      fail(this.loadError);
    }
  };

  private handleEnded = () => {
    if (this.pendingSeek) {
      if (
        this.pendingSeek.applied &&
        this.pendingSeek.loadId === this.sourceLoadId &&
        this.metadataLoaded &&
        this.hasCurrentMetadata() &&
        this.player.ended()
      ) {
        this.pendingSeek.ended = true;
      }
      return;
    }
    if (this.completed || this.holdEndpoint || !this.metadataLoaded || !this.hasCurrentMetadata()) {
      return;
    }
    if (this.tail) {
      this.player.trigger(this.tail.startedAt === undefined ? 'pause' : 'play');
      return;
    }
    const handle = this.currentPlayingHandle();
    const time = this.clipTime();
    if (handle && time < handle.souce.duration) {
      const tail = { time, rate: this.player.playbackRate() ?? 1 };
      this.tail = tail;
      this.refreshFinalFrame();
      if (this.tail !== tail || this.disposed || this.loadError) {
        return;
      }
      this.publishObservation(handle, 'ready');
      if (this.tail === tail && !this.pauseRequested && !this.disposed) {
        this.startTail();
      }
      return;
    }
    this.finishClip();
  };

  private startTail() {
    const tail = this.tail;
    if (!tail || tail.startedAt !== undefined || this.disposed) {
      return;
    }
    tail.startedAt = performance.now();
    tail.rate = this.player.playbackRate() ?? 1;
    this.player.trigger('play');
    const tick = () => {
      const handle = this.currentPlayingHandle();
      if (this.tail !== tail || tail.startedAt === undefined || !handle) {
        return;
      }
      this.sampleTail();
      if (tail.time >= handle.souce.duration) {
        this.finishClip();
        return;
      }
      this.publishObservation(handle, 'ready');
      if (this.tail === tail && tail.startedAt !== undefined) {
        tail.timer = setTimeout(tick, Math.min(100, ((handle.souce.duration - tail.time) / tail.rate) * 1000));
      }
    };
    tick();
  }

  private stopTail() {
    if (this.tail) {
      this.sampleTail();
      clearTimeout(this.tail.timer);
      this.tail.startedAt = undefined;
    }
  }

  private sampleTail() {
    const tail = this.tail;
    const handle = this.currentPlayingHandle();
    if (tail?.startedAt !== undefined && handle) {
      const now = performance.now();
      tail.time = Math.min(handle.souce.duration, tail.time + ((now - tail.startedAt) / 1000) * tail.rate);
      if (handle.souce.duration - tail.time < 1e-9) {
        tail.time = handle.souce.duration;
      }
      tail.startedAt = now;
    }
  }

  private handleRateChange = () => {
    this.sampleTail();
    if (this.tail) {
      this.tail.rate = this.player.playbackRate() ?? 1;
    }
  };

  private refreshFinalFrame() {
    const duration = this.player.duration();
    // An uncued WebM's last frame can start exactly at its duration and be skipped at EOF.
    if (Number.isFinite(duration) && duration === this.player.currentTime()) {
      try {
        this.player.currentTime(duration);
      } catch (error) {
        console.error('Final frame seek failed:', error);
      }
    }
  }

  private finishClip() {
    this.stopTail();
    const handle = this.currentPlayingHandle();
    if (handle) {
      const next = this.handles[handle.index + 1];
      const loadId = this.sourceLoadId;
      const commandId = this.playbackCommandId;
      this.completed = !next;
      if (!next) {
        finishPlayback(this.player);
        if (!this.tail && this.player.ended()) {
          this.refreshFinalFrame();
        }
      }
      if (this.sourceLoadId !== loadId || this.pendingSeek || this.disposed || this.loadError) {
        return;
      }
      this.publishObservation(handle, next ? 'ready' : 'ended');
      if (this.sourceLoadId !== loadId || this.pendingSeek || this.disposed) {
        return;
      }
      handle.status = { status: 'ended' };
      if (!next) {
        if (this.tail) {
          this.player.trigger('ended');
        }
        return;
      }
      try {
        this.setSource(
          next,
          !this.pauseRequested && (commandId === this.playbackCommandId || playbackIntent(this.player)),
        );
      } catch (error) {
        console.error('Playback failed:', error);
      }
    }
  }
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
