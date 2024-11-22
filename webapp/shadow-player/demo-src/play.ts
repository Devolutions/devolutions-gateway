import { getInfoFile, getStreamingWebsocketUrl } from './apiClient';
import { ShadowPlayer } from '../src/streamer';

// Function to play the selected stream
export async function playStream(id: string) {
  const websocketUrl = await getStreamingWebsocketUrl(id);

  const videoElement = document.getElementById('shadowPlayer') as ShadowPlayer;
  videoElement.srcChange(websocketUrl);
  videoElement.play()
}

export function download() {
  const videoElement = document.getElementById('shadowPlayer') as ShadowPlayer;
  videoElement.downloadBUfferAsFile();
}
