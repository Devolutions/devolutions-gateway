import { GatewayAccessApi } from './gateway';
import { showNotification } from './notification.ts';
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
    BeforeWebsocketClose((closeEvent) => beforeWebsocketCloseHandler(closeEvent, gatewayAccessApi));

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

function beforeWebsocketCloseHandler(closeEvent, gatewayAccessApi) {
  if (closeEvent.code >= 4000) {
    if (closeEvent.code === StreamerWebsocketCloseCode.StreamingEnded) {
      cleanUpStreamers();
      playStaticRecording(gatewayAccessApi);
      showNotification('Streaming has finished, play recording as fallback', 'success');
    }

    if (closeEvent.code === StreamerWebsocketCloseCode.InternalError) {
      showNotification('Internal error, please try again', 'error');
    }

    if (closeEvent.code === StreamerWebsocketCloseCode.Forbidden) {
      showNotification('You are not authorized to play this recording', 'error');
    }

    // This prevents extra handling by other listeners, particularly for asciinema-player in this scenario.
    // For more details, see the asciinema-player WebSocket driver’s socket close handler.
    // https://github.com/asciinema/asciinema-player/blob/c09e1d2625450a32e9e76063cdc315fd54ecdd9d/src/driver/websocket.js#L219
    return {
      ...closeEvent,
      code: 1000,
    };
  }

  if (closeEvent.code !== 1000 || closeEvent.code !== 1005) {
    showNotification('Unknown error, please try again', 'error');
    return {
      ...closeEvent,
      code: 1000,
    };
  }

  return closeEvent;
}

enum StreamerWebsocketCloseCode {
  StreamingEnded = 4001,
  InternalError = 4002,
  Forbidden = 4003,
}

main();
