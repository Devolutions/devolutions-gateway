import '@devolutions/shadow-player';
import type { ShadowPlayer } from '@devolutions/shadow-player';
import { GatewayAccessApi } from '../gateway';
import { t } from '../i18n';
import { showNotification } from '../notification';

export async function handleWebm(gatewayAccessApi: GatewayAccessApi) {
  const shadowPlayer = document.createElement('shadow-player') as ShadowPlayer;
  shadowPlayer.setAttribute('controls', '');
  shadowPlayer.setControlLabels({
    play: t('controls.play'),
    pause: t('controls.pause'),
    mute: t('controls.mute'),
    unmute: t('controls.unmute'),
    volume: t('controls.volume'),
    timeline: t('controls.timeline'),
    fullscreen: t('controls.fullscreen'),
    exitFullscreen: t('controls.exitFullscreen'),
    clip: t('controls.clip'),
  });

  document.body.appendChild(shadowPlayer);

  await customElements.whenDefined('shadow-player');
  await new Promise((resolve) => setTimeout(resolve, 0));

  shadowPlayer.srcChange(gatewayAccessApi.sessionShadowingUrl());
  shadowPlayer.play();

  shadowPlayer.onError((error) => {
    if (error.type === 'protocol') {
      showNotification(t('notifications.protocolError', { error: error.inner.error }), 'error');
    }
  });

  return shadowPlayer;
}
