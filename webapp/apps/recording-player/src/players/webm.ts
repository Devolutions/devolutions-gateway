import '@devolutions/multi-video-player';
import '@devolutions/multi-video-player/dist/multi-video-player.css';
import { MultiVideoPlayer } from '@devolutions/multi-video-player';
import type { GatewayAccessApi } from '../gateway';

export async function handleWebm(gatewayApi: GatewayAccessApi) {
  await new Promise((resolve) => setTimeout(resolve, 0));
  await customElements.whenDefined('multi-video-player');
  const videoPlayer = document.createElement('multi-video-player') as MultiVideoPlayer;

  videoPlayer.setAttribute('width', '100%');
  videoPlayer.setAttribute('height', '100%');
  videoPlayer.setAttribute('controls', '');
  videoPlayer.setAttribute('muted', '');
  videoPlayer.setAttribute('autoplay', '');
  document.body.appendChild(videoPlayer);

  videoPlayer.play(
    gatewayApi.info().recordingInfo.files.map((file) => ({
      src: gatewayApi.staticRecordingUrl(file.fileName),
      type: 'video/webm',
      duration: file.duration,
    })),
  );
}
