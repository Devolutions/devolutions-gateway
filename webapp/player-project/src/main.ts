import { GatewayAccessApi } from './gateway';
import { getPlayer } from './players/index.js';
import { getShadowPlayer } from './streamers/index.js';

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
