import { ensureNoSameTimeCues } from '../cast-parser.js';
import { createTerminalDiv, loadFile } from './index.js';

export async function handleCast(recordingInfo, gatewayAccessUrl, sessionId, token) {
  const terminalDiv = createTerminalDiv();
  const castSrc = `${gatewayAccessUrl}/jet/jrec/pull/${sessionId}/${recordingInfo.files[0].fileName}?token=${token}`;

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
