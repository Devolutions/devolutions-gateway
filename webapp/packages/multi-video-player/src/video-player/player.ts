import videojs from 'video.js';
import Player from 'video.js/dist/types/player';
import './progress-control';
import { ProgressManager } from '../progress-manager';
import { MaybeResolvedPromise } from '../util';
import { MultiVideoProgressControl } from './progress-control';

export interface SourceMetadata {
  src: string;
  duration: number;
  type: string;
}

// Define Web Component
export class MultiVideoPlayer extends HTMLElement {
  private player: Player | null = null;
  private videoElement: HTMLVideoElement | null = null;
  private ready = new MaybeResolvedPromise<void>();
  private attributesMap = new Map<string, string>();

  constructor() {
    super();
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
        controlBar: {
          children: ['playToggle', 'volumePanel', 'MultiVideoProgressControl', 'fullscreenToggle'],
        },
        fill: true,
      });

      this.player.ready(() => {
        this.ready.resolve();
      });
    } catch (error) {
      this.ready.reject(error);
    }
  }

  async play(playList: SourceMetadata[]) {
    await this.ready.wait(); // Ensures readiness before continuing

    if (!this.player || playList.length === 0) {
      console.warn('Player not initialized yet!');
      return;
    }

    for (const source of playList) {
      if (typeof source.duration !== 'number') {
        source.duration = Number.parseInt(source.duration as string, 10);
      }
    }

    const firstVideo = playList[0];
    this.player.src({
      src: firstVideo.src,
      type: firstVideo.type,
    });

    const progressControl = this.progressControl();
    if (progressControl) {
      progressControl.setProgressManager(new ProgressManager(this.player, playList));
    } else {
      console.warn('Progress control not found!');
    }
  }

  private progressControl(): MultiVideoProgressControl | null {
    return this.player
      ?.getChild('controlBar')
      ?.getChild('MultiVideoProgressControl') as MultiVideoProgressControl | null;
  }
}

customElements.define('multi-video-player', MultiVideoPlayer);
