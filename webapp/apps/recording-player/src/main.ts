import { GatewayAccessApi } from './gateway';
import { showNotification } from './notification.ts';
import { getPlayer } from './players/index.js';
import { cleanUpStreamers, getShadowPlayer } from './streamers/index.js';
import './ws-proxy.ts';
import { setupI18n, t } from './i18n';
import { OnBeforeClose as BeforeWebsocketClose } from './ws-proxy.ts';

async function main() {
  const { sessionId, token, gatewayAccessUrl, isActive, language } = getSessionDetails();

  const gatewayAccessApi = GatewayAccessApi.builder()
    .gatewayAccessUrl(gatewayAccessUrl)
    .token(token)
    .sessionId(sessionId)
    .build();

  await setupI18n(gatewayAccessApi, language);

  // shawdow session
  if (isActive) {
    await playSessionShadowing(gatewayAccessApi);
  } else {
    await playStaticRecording(gatewayAccessApi);
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
  const isActive = windowURL.searchParams.get('isActive') === 'true';
  const language = windowURL.searchParams.get('lang');

  return { sessionId, token, gatewayAccessUrl, isActive, language };
}

function getFileType(recordingInfo) {
  return recordingInfo.files[0].fileName.split('.')[1];
}

function beforeWebsocketCloseHandler(closeEvent, gatewayAccessApi) {
  if (closeEvent.code >= 4000) {
    if (closeEvent.code === StreamerWebsocketCloseCode.StreamingEnded) {
      cleanUpStreamers();
      playStaticRecording(gatewayAccessApi);
      showNotification(t('notifications.streamingFinished'), 'success');
    }

    if (closeEvent.code === StreamerWebsocketCloseCode.InternalError) {
      showNotification(t('notifications.internalError'), 'error');
    }

    if (closeEvent.code === StreamerWebsocketCloseCode.Forbidden) {
      showNotification(t('notifications.unauthorized'), 'error');
    }

    // This prevents extra handling by other listeners, particularly for asciinema-player in this scenario.
    // For more details, see the asciinema-player WebSocket driver's socket close handler.
    // https://github.com/asciinema/asciinema-player/blob/c09e1d2625450a32e9e76063cdc315fd54ecdd9d/src/driver/websocket.js#L219
    return {
      ...closeEvent,
      code: 1000,
    };
  }

  if (closeEvent.code !== 1000 && closeEvent.code !== 1005) {
    showNotification(t('notifications.unknownError'), 'error');
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
