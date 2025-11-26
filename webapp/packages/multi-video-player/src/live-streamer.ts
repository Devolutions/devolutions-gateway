import '@devolutions/shadow-player';
import type { ShadowPlayer, ShadowPlayerError } from '@devolutions/shadow-player';
import type { MultiVideoPlayer } from './video-player/player';
import type { GatewayRecordingApi } from './gateway-api';

export class LiveRecordingStreamer {
  private shadowPlayer: ShadowPlayer | null = null;
  private api: GatewayRecordingApi;
  private onSessionNotFoundCallback: (() => void) | null = null;

  constructor(api: GatewayRecordingApi) {
    this.api = api;
  }

  onSessionNotFound(callback: () => void): void {
    this.onSessionNotFoundCallback = callback;
  }

  async stream(container: HTMLElement): Promise<ShadowPlayer> {
    const shadowUrl = this.api.getShadowUrl();

    this.shadowPlayer = document.createElement('shadow-player') as ShadowPlayer;
    this.shadowPlayer.setAttribute('controls', '');
    this.shadowPlayer.setAttribute('width', '100%');
    this.shadowPlayer.setAttribute('height', '100%');

    this.shadowPlayer.onError((error: ShadowPlayerError) => {
      if (error.type === 'session-not-found') {
        this.onSessionNotFoundCallback?.();
      }
    });

    container.appendChild(this.shadowPlayer);

    await customElements.whenDefined('shadow-player');
    await new Promise((resolve) => setTimeout(resolve, 0));

    this.shadowPlayer.srcChange(shadowUrl);
    this.shadowPlayer.play();

    return this.shadowPlayer;
  }

  async streamAndTransition(
    container: HTMLElement,
    staticPlayer: MultiVideoPlayer
  ): Promise<void> {
    const shadowPlayer = await this.stream(container);

    shadowPlayer.onEnd(async () => {
      container.removeChild(shadowPlayer);

      const metadata = await this.api.fetchMetadata();
      await staticPlayer.play(
        metadata.files.map(file => ({
          src: this.api.getSegmentUrl(file.fileName),
          type: 'video/webm',
          duration: file.duration
        }))
      );
    });
  }

  disconnect(): void {
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
