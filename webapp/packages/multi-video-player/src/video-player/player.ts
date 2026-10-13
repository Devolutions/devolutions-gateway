import videojs from 'video.js';
import Player from 'video.js/dist/types/player';
import './progress-control';
import { ProgressManager, playableSource } from '../progress-manager';
import { MaybeResolvedPromise } from '../util';
import { MultiVideoProgressControl } from './progress-control';

export interface SourceMetadata {
  src: string;
  duration: number;
  type: string;
}

export interface MultiVideoPlayerEventMap extends HTMLElementEventMap {
  timeupdate: CustomEvent<{ currentTime: number; clipIndex: number }>;
  clipchange: CustomEvent<{ clipIndex: number }>;
}

// Define Web Component
export class MultiVideoPlayer extends HTMLElement {
  private player: Player | null = null;
  private videoElement: HTMLVideoElement | null = null;
  private ready = new MaybeResolvedPromise<void>();
  private attributesMap = new Map<string, string>();
  private progressManager: ProgressManager | null = null;
  private disposed = false;
  private playRequest = 0;

  constructor() {
    super();
  }

  declare addEventListener: (<K extends keyof MultiVideoPlayerEventMap>(
    type: K,
    listener: (this: MultiVideoPlayer, event: MultiVideoPlayerEventMap[K]) => void,
    options?: false | (AddEventListenerOptions & { capture?: false }),
  ) => void) &
    HTMLElement['addEventListener'];

  declare removeEventListener: (<K extends keyof MultiVideoPlayerEventMap>(
    type: K,
    listener: (this: MultiVideoPlayer, event: MultiVideoPlayerEventMap[K]) => void,
    options?: false | (EventListenerOptions & { capture?: false }),
  ) => void) &
    HTMLElement['removeEventListener'];

  get currentTime(): number {
    return this.progressManager?.currentTime ?? 0;
  }

  get duration(): number {
    return this.progressManager?.duration ?? 0;
  }

  get currentClipIndex(): number {
    return this.progressManager?.currentPlayingHandle()?.index ?? -1;
  }

  async seek(seconds: number): Promise<void> {
    if (!Number.isFinite(seconds)) {
      throw new RangeError('seek time must be finite');
    }
    if (this.disposed) {
      throw new DOMException('player is disposed', 'InvalidStateError');
    }
    await this.progressManager?.seek(seconds);
  }

  async resume(): Promise<void> {
    if (this.disposed) {
      throw new DOMException('player is disposed', 'InvalidStateError');
    }
    await this.progressManager?.resume();
  }

  static get observedAttributes() {
    return ['width', 'height', 'controls', 'autoplay', 'muted'];
  }

  attributeChangedCallback(name: string, _oldValue: string, newValue: string) {
    this.attributesMap.set(name, newValue);
    this.assignAttributes();
  }

  private assignAttributes() {
    for (const [name, value] of this.attributesMap.entries()) {
      if (this.videoElement) {
        if (['controls', 'autoplay', 'muted'].includes(name)) {
          if (this.hasAttribute(name)) {
            this.videoElement.setAttribute(name, '');
          } else {
            this.videoElement.removeAttribute(name);
          }
        } else {
          this.videoElement.setAttribute(name, value);
        }
      }
    }
  }

  connectedCallback() {
    if (this.player) {
      return;
    }
    if (this.disposed) {
      this.ready = new MaybeResolvedPromise<void>();
      this.disposed = false;
    }
    // Create and attach video element inside the component
    this.innerHTML = `
        <style>
        multi-video-player {
          height: 95%;
          width: 95%;
        }

      </style>
      <video id="my-video" class="video-js vjs-default-skin">
        Your browser does not support the video tag.
      </video>
    `;
    this.videoElement = this.querySelector('video');
    this.assignAttributes();

    if (!this.videoElement) {
      this.ready.reject(new Error('Video element not found!'));
      return;
    }

    try {
      this.player = videojs(this.videoElement, {
        enableSourceset: true,
        controlBar: {
          children: ['playToggle', 'volumePanel', 'MultiVideoProgressControl', 'fullscreenToggle'],
        },
        fill: true,
      });

      const ready = this.ready;
      this.player.ready(() => {
        ready.resolve();
      });
    } catch (error) {
      this.ready.reject(error);
    }
  }

  async play(playList: SourceMetadata[]) {
    const request = ++this.playRequest;
    await this.ready.wait(); // Ensures readiness before continuing

    if (this.disposed || request !== this.playRequest) {
      return;
    }
    if (!this.player || playList.length === 0) {
      console.warn('Player not initialized yet!');
      return;
    }

    for (const source of playList) {
      if (typeof source.duration !== 'number') {
        source.duration = Number.parseInt(source.duration as string, 10);
      }
      if (!Number.isFinite(source.duration) || source.duration < 0) {
        throw new RangeError('source duration must be finite and nonnegative');
      }
    }

    playableSource(this.player, playList[0]);
    this.progressManager?.dispose();
    this.progressManager = new ProgressManager(
      this.player,
      playList,
      () =>
        this.dispatchEvent(
          new CustomEvent('timeupdate', {
            detail: { currentTime: this.currentTime, clipIndex: this.currentClipIndex },
          }),
        ),
      () =>
        this.dispatchEvent(
          new CustomEvent('clipchange', {
            detail: { clipIndex: this.currentClipIndex },
          }),
        ),
    );

    const progressControl = this.progressControl();
    if (progressControl) {
      progressControl.setProgressManager(this.progressManager);
    } else {
      console.warn('Progress control not found!');
    }
    this.progressManager.start();
  }

  pause() {
    this.progressManager?.pause();
    if (this.player) {
      try {
        this.player.pause();
      } catch {
        // ignore pause errors
      }
    }
  }

  private progressControl(): MultiVideoProgressControl | null {
    return this.player
      ?.getChild('controlBar')
      ?.getChild('MultiVideoProgressControl') as MultiVideoProgressControl | null;
  }

  async dispose() {
    this.disposed = true;
    ++this.playRequest;
    this.ready.resolve();
    this.progressManager?.dispose();
    this.progressManager = null;
    const player = this.player;
    this.player = null;
    this.videoElement = null;
    if (player) {
      try {
        // pause the player first to avoid AbortError
        player.pause();
        await new Promise((resolve) => setTimeout(resolve, 0));
        player.dispose();
      } catch (error) {
        // ignore errors when disposing
        console.debug('Error during player disposal:', error);
      }
    }
  }

  disconnectedCallback() {
    this.dispose();
  }
}

customElements.define('multi-video-player', MultiVideoPlayer);
