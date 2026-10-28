import '@devolutions/shadow-player';
import type { ShadowPlayer, ShadowPlayerError } from '@devolutions/shadow-player';
import type { GatewayRecordingApi } from './gateway-api';
import type { MultiVideoPlayer } from './video-player/player';

export interface LiveRecordingStreamOptions {
  controls?: boolean;
  onReady?: () => void;
  onEnd?: () => void;
  onError?: (error: ShadowPlayerError) => void;
}

export class LiveRecordingStreamer {
  private shadowPlayer: ShadowPlayer | null = null;
  private api: GatewayRecordingApi;
  private onSessionNotFoundCallback: (() => void) | null = null;
  private streamRequest = 0;
  private pendingSetup: AbortController | null = null;

  constructor(api: GatewayRecordingApi) {
    this.api = api;
  }

  onSessionNotFound(callback: () => void): void {
    this.onSessionNotFoundCallback = callback;
  }

  async stream(container: HTMLElement, options: LiveRecordingStreamOptions = {}): Promise<ShadowPlayer> {
    this.disconnect();
    const request = this.streamRequest;
    const setup = new AbortController();
    this.pendingSetup = setup;
    let cancelled!: () => void;
    const cancellation = new Promise<never>((_resolve, reject) => {
      cancelled = () => reject(new DOMException('stream setup interrupted', 'AbortError'));
      setup.signal.addEventListener('abort', cancelled, { once: true });
    });
    try {
      await Promise.race([customElements.whenDefined('shadow-player'), cancellation]);
      if (request !== this.streamRequest) {
        throw new DOMException('stream setup interrupted', 'AbortError');
      }
      const shadowUrl = this.api.getShadowUrl();

      const player = document.createElement('shadow-player') as ShadowPlayer;
      this.shadowPlayer = player;
      if (options.controls === false) {
        if (typeof player.setControls !== 'function') {
          throw new Error('Installed ShadowPlayer does not support controls: false');
        }
        player.setControls(false);
      } else {
        player.setAttribute('controls', '');
      }
      player.setAttribute('width', '100%');
      player.setAttribute('height', '100%');

      player.onError((error) => {
        if (request !== this.streamRequest || this.shadowPlayer !== player) {
          return;
        }
        if (error.type === 'session-not-found') {
          try {
            this.onSessionNotFoundCallback?.();
          } catch {
            console.error('Session-not-found callback failed');
          }
        }
        if (request !== this.streamRequest || this.shadowPlayer !== player) {
          return;
        }
        if (options.onError) {
          options.onError(error);
        } else if (error.type !== 'session-not-found') {
          console.error('Live recording failed:', error.type);
        }
      });
      if (options.onReady) {
        if (typeof player.onReady !== 'function') {
          throw new Error('Installed ShadowPlayer does not support onReady');
        }
        player.onReady(() => {
          if (request === this.streamRequest && this.shadowPlayer === player) {
            return options.onReady?.();
          }
        });
      }
      if (options.onEnd) {
        player.onEnd(() => {
          if (request === this.streamRequest && this.shadowPlayer === player) {
            return options.onEnd?.();
          }
        });
      }
      container.appendChild(player);
      player.srcChange(shadowUrl);
      if (request !== this.streamRequest || this.shadowPlayer !== player) {
        throw new DOMException('stream setup interrupted', 'AbortError');
      }
      player.play();

      return player;
    } catch (error) {
      if (request === this.streamRequest) {
        this.disconnect();
      }
      throw error;
    } finally {
      setup.signal.removeEventListener('abort', cancelled);
      if (this.pendingSetup === setup) {
        this.pendingSetup = null;
      }
    }
  }

  async streamAndTransition(container: HTMLElement, staticPlayer: Pick<MultiVideoPlayer, 'play'>): Promise<void> {
    await this.stream(container, {
      onEnd: async () => {
        const request = this.streamRequest;
        const player = this.shadowPlayer;
        player?.remove();
        try {
          const metadata = await this.api.fetchMetadata();
          if (request !== this.streamRequest) {
            return;
          }
          await staticPlayer.play(
            metadata.files.map((file) => ({
              src: this.api.getSegmentUrl(file.fileName),
              type: 'video/webm',
              duration: file.duration,
            })),
          );
        } catch {
          if (request === this.streamRequest) {
            console.error('Live recording transition failed');
          }
        } finally {
          if (this.shadowPlayer === player) {
            this.shadowPlayer = null;
          }
        }
      },
    });
  }

  disconnect(): void {
    ++this.streamRequest;
    const setup = this.pendingSetup;
    this.pendingSetup = null;
    setup?.abort();
    if (this.shadowPlayer) {
      this.shadowPlayer.disconnect();

      if (this.shadowPlayer.parentElement) {
        this.shadowPlayer.parentElement.removeChild(this.shadowPlayer);
      }
    }
    this.shadowPlayer = null;
  }

  isConnected(): boolean {
    return this.shadowPlayer !== null && this.shadowPlayer.parentElement !== null;
  }
}
