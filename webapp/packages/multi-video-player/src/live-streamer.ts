import '@devolutions/shadow-player/src/streamer';
import type { ShadowPlayer } from '@devolutions/shadow-player/src/streamer';
import type { MultiVideoPlayer } from './video-player/player';
import type { GatewayRecordingApi } from './gateway-api';

export class LiveRecordingStreamer {
  private shadowPlayer: ShadowPlayer | null = null;
  private api: GatewayRecordingApi;

  constructor(api: GatewayRecordingApi) {
    this.api = api;
  }

  async stream(container: HTMLElement): Promise<ShadowPlayer> {
    this.shadowPlayer = document.createElement('shadow-player') as ShadowPlayer;
    container.appendChild(this.shadowPlayer);

    await customElements.whenDefined('shadow-player');
    await new Promise((resolve) => setTimeout(resolve, 0));

    this.shadowPlayer.srcChange(this.api.getShadowUrl());
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
    if (this.shadowPlayer && this.shadowPlayer.parentElement) {
      this.shadowPlayer.parentElement.removeChild(this.shadowPlayer);
    }
    this.shadowPlayer = null;
  }

  isConnected(): boolean {
    return this.shadowPlayer !== null && this.shadowPlayer.parentElement !== null;
  }
}
