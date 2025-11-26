import '@devolutions/shadow-player';
import type { ShadowPlayer } from '@devolutions/shadow-player';
import { GatewayAccessApi } from '../gateway';
import { t } from '../i18n';
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
    if (error.type === 'protocol') {
      showNotification(t('notifications.protocolError', { error: error.inner.error }), 'error');
    }
  });

  return shadowPlayer;
}
