import { ensureNoSameTimeCues } from '../cast-parser.js';
import { GatewayAccessApi } from '../gateway.js';
import { createTerminal } from '../terminal.js';
import { loadFile } from './index.js';

export async function handleCast(gatewayApi: GatewayAccessApi) {
  const castSrc = gatewayApi.staticRecordingUrl(gatewayApi.recordingInfo.files[0].fileName);

  try {
    const castFileContent = await loadFile(castSrc);
    const fixedContent = ensureNoSameTimeCues(new TextDecoder().decode(castFileContent));
    const objectUrl = URL.createObjectURL(new Blob([fixedContent], { type: 'text/plain' }));
    const player = createTerminal(objectUrl);
    setTimeout(() => player.play(), 500);
  } catch (error) {
    console.error(error);
  }
}
