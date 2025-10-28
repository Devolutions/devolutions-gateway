import { GatewayAccessApi } from '../gateway';
import { createTerminal } from '../terminal';
import { convertTRPtoCast } from '../trp-decoder';
import { loadFile, overrideFetch, restoreFetch } from '.';

export async function handleTrp(gatewayApi: GatewayAccessApi) {
  const trpSrc = gatewayApi.staticRecordingUrl(gatewayApi.recordingInfo.files[0].fileName);

  try {
    const trpFileContent = await loadFile(trpSrc);
    const castFileContent = convertTRPtoCast(trpFileContent);
    const objectUrl = URL.createObjectURL(new Blob([castFileContent], { type: 'text/plain' }));

    overrideFetch(objectUrl, castFileContent);
    const player = createTerminal(objectUrl);
    restoreFetch();

    setTimeout(() => player.play(), 500);
  } catch (error) {
    console.error(error);
  }
}
