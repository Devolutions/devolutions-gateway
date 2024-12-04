import { createTerminalDiv, loadFile, overrideFetch, restoreFetch } from './index.js';

import { convertTRPtoCast } from '../trp-decoder.js';

/**
 * Handles the playback of TRP files using the provided gateway API.
 *
 * @param {GatewayAccessApi} gatewayApi - The API to access the gateway for video streaming.
 */

export async function handleTrp(gatewayApi) {
  const terminalDiv = createTerminalDiv();
  const trpSrc = gatewayApi.staticRecordingUrl(gatewayApi.recordingInfo.files[0].fileName);

  try {
    const trpFileContent = await loadFile(trpSrc);
    const castFileContent = convertTRPtoCast(trpFileContent);
    const objectUrl = URL.createObjectURL(new Blob([castFileContent], { type: 'text/plain' }));

    overrideFetch(objectUrl, castFileContent);
    const player = new XtermPlayer.XtermPlayer(objectUrl, terminalDiv);
    restoreFetch();

    setTimeout(() => player.play(), 500);
  } catch (error) {
    console.error(error);
  }
}
