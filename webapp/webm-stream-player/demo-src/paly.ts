import { getInfoFile, getStreamingWebsocketUrl } from './apiClient';
import { WebmStreamPlayer } from '../src/streamer';

// Function to play the selected stream
export async function playStream(id: string) {
  const websocketUrl = await getStreamingWebsocketUrl(id);

  const videoElement = document.getElementById('webmPlayer') as WebmStreamPlayer;
  videoElement.srcChange(websocketUrl);
}
