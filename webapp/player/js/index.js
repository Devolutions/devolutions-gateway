import { getPlayer } from "./players/index.js";

async function main() {
  const { sessionId, token, gatewayAccessUrl } = getSessionDetails();
  const videoSrcInfo = `${gatewayAccessUrl}/jet/jrec/pull/${sessionId}/recording.json?token=${token}`;

  try {
    const recordingInfo = await fetchRecordingInfo(videoSrcInfo);
    const fileType = getFileType(recordingInfo);

    getPlayer(fileType).play(recordingInfo, gatewayAccessUrl, sessionId, token);
  } catch (error) {
    console.error(error);
  }
}

function getSessionDetails() {
  const windowURL = new URL(window.location.href);
  const sessionId = windowURL.searchParams.get("sessionId");
  const token = windowURL.searchParams.get("token");
  const gatewayAccessUrl = windowURL.toString().split("/jet/jrec")[0];
  return { sessionId, token, gatewayAccessUrl };
}

async function fetchRecordingInfo(url) {
  const response = await fetch(url);
  if (!response.ok) {
    throw new Error(`Request failed. Returned status of ${response.status}`);
  }
  return response.json();
}

function getFileType(recordingInfo) {
  return recordingInfo.files[0].fileName.split(".")[1];
}

main();
