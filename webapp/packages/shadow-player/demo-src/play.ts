import { ShadowPlayer } from '../src/streamer';
import { getStreamingWebsocketUrl } from './apiClient';

// Function to play the selected stream
export async function playStream(id: string) {
  const websocketUrl = await getStreamingWebsocketUrl(id);

  const videoElement = document.getElementById('shadowPlayer') as ShadowPlayer;
  videoElement.setDebug(true);
  videoElement.srcChange(websocketUrl);
  videoElement.play();
}

export function download() {
  const videoElement = document.getElementById('shadowPlayer') as ShadowPlayer;
  videoElement.downloadBUfferAsFile();
}
