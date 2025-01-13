import '../../../shadow-player/src/streamer';
import { ShadowPlayer } from '../../../shadow-player/src/streamer';
import { GatewayAccessApi } from '../gateway';
import { showNotification } from '../notification';

export async function handleWebm(gatewayAccessApi: GatewayAccessApi) {
  // Create element with correct spelling
  const shadowPlayer = document.createElement('shadow-player') as ShadowPlayer;

  // Append to DOM
  document.body.appendChild(shadowPlayer);

  // Wait for element to be initialized
  await customElements.whenDefined('shadow-player');

  // Wait for next microtask to ensure connectedCallback has run
  await new Promise((resolve) => setTimeout(resolve, 0));

  // Now safe to call methods
  shadowPlayer.srcChange(gatewayAccessApi.sessionShadowingUrl());
  shadowPlayer.play();

  shadowPlayer.onError((error) => {
    let errorMessage = 'An error occurred';

    if (error.type === 'protocol') {
      errorMessage = `An error occurred: ${error.inner.error}`;
    } else {
      errorMessage = `An error occurred: ${error.inner.message}`;
    }
    showNotification(errorMessage, 'error');
  });

  return shadowPlayer;
}
