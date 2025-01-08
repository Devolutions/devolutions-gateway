import { GatewayAccessApi } from '../gateway';
import { createTerminal } from '../terminal';

export async function handleCast(gatewayAccessApi: GatewayAccessApi) {
  const websocket = gatewayAccessApi.sessionShadowingUrl().toString();

  window.WebSocket;
  const player = createTerminal(websocket);
  player.addEventListener('ended', () => {
    console.log('ended!');
  });

  await player.play();
}
