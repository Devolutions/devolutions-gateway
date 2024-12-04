import { ensureNoSameTimeCues } from '../cast-parser.js';
import { createTerminalDiv, loadFile } from './index.js';

/**
 * Handles the playback of CAST files using the provided gateway API.
 *
 * @param {GatewayAccessApi} gatewayApi - The API to access the gateway for video streaming.
 */
export async function handleCast(gatewayApi) {
  const terminalDiv = createTerminalDiv();
  const castSrc = gatewayApi.staticRecordingUrl(gatewayApi.recordingInfo.files[0].fileName);

  try {
    const castFileContent = await loadFile(castSrc);
    const fixedContent = ensureNoSameTimeCues(new TextDecoder().decode(castFileContent));
    const objectUrl = URL.createObjectURL(new Blob([fixedContent], { type: 'text/plain' }));

    const player = new XtermPlayer.XtermPlayer(objectUrl, terminalDiv);
    setTimeout(() => player.play(), 500);
  } catch (error) {
    console.error(error);
  }
}
