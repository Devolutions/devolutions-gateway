import { GatewayAccessApi } from '../gateway';
import { createTerminal } from '../terminal';

export async function handleCast(gatewayAccessApi: GatewayAccessApi) {
  const websocket = gatewayAccessApi.sessionShadowingUrl().toString();

  const player = createTerminal(websocket);

  await player.play();
}
