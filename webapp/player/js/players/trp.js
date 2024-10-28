import {
  createTerminalDiv,
  overrideFetch,
  restoreFetch,
  loadFile,
} from "./index.js";

import { convertTRPtoCast } from "../trp-decoder.js";

export async function handleTrp(
  recordingInfo,
  gatewayAccessUrl,
  sessionId,
  token
) {
  const terminalDiv = createTerminalDiv();
  const trpSrc = `${gatewayAccessUrl}/jet/jrec/pull/${sessionId}/${recordingInfo.files[0].fileName}?token=${token}`;

  try {
    const trpFileContent = await loadFile(trpSrc);
    const castFileContent = convertTRPtoCast(trpFileContent);
    const objectUrl = URL.createObjectURL(
      new Blob([castFileContent], { type: "text/plain" })
    );

    overrideFetch(objectUrl, castFileContent);
    const player = new XtermPlayer.XtermPlayer(objectUrl, terminalDiv);
    restoreFetch();

    setTimeout(() => player.play(), 500);
  } catch (error) {
    console.error(error);
  }
}
