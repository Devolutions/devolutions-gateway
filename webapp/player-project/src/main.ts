import { GatewayAccessApi } from './gateway';
import { getPlayer } from './players/index.js';
import { cleanUpStreamers, getShadowPlayer } from './streamers/index.js';
import './ws-proxy.ts';
import { OnBeforeClose as BeforeWebsocketClose } from './ws-proxy.ts';

async function main() {
  const { sessionId, token, gatewayAccessUrl, isActive } = getSessionDetails();

  const getewayAccessApi = GatewayAccessApi.builder()
    .gatewayAccessUrl(gatewayAccessUrl)
    .token(token)
    .sessionId(sessionId)
    .build();

  // shawdow session
  if (isActive) {
    await playSessionShadowing(getewayAccessApi);
  } else {
    await playStaticRecording(getewayAccessApi);
  }
}

async function playSessionShadowing(gatewayAccessApi) {
  try {
    const recordingInfo = await gatewayAccessApi.fetchRecordingInfo();
    const fileType = getFileType(recordingInfo);
    BeforeWebsocketClose((closeEvent) => {
      if (closeEvent.code !== 1000) {
        // The session playback failed; attempt to play the recording as usual as a fallback.
        cleanUpStreamers();
        playStaticRecording(gatewayAccessApi);
        return {
          ...closeEvent,
          // This prevents extra handling by other listeners, particularly for asciinema-player in this scenario.
          // For more details, see the asciinema-player WebSocket driver’s socket close handler.
          // https://github.com/asciinema/asciinema-player/blob/c09e1d2625450a32e9e76063cdc315fd54ecdd9d/src/driver/websocket.js#L219
          code: 1000,
        };
      }
    });

    getShadowPlayer(fileType).play(gatewayAccessApi);
  } catch (error) {
    console.error(error);
  }
}

async function playStaticRecording(gatewayAccessApi) {
  try {
    const recordingInfo = await gatewayAccessApi.fetchRecordingInfo();
    const fileType = getFileType(recordingInfo);

    getPlayer(fileType).play(gatewayAccessApi);
  } catch (error) {
    console.error(error);
  }
}

function getSessionDetails() {
  const windowURL = new URL(window.location.href);
  const sessionId = windowURL.searchParams.get('sessionId');
  const token = windowURL.searchParams.get('token');
  const gatewayAccessUrl = windowURL.toString().split('/jet/jrec')[0];
  const isActive = windowURL.searchParams.get('isActive') || false;
  return { sessionId, token, gatewayAccessUrl, isActive };
}

function getFileType(recordingInfo) {
  return recordingInfo.files[0].fileName.split('.')[1];
}

main();
