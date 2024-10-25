import '../generated/webm-stream-player.js';
import { ShadowPlayer } from '../generated/webm-stream-player.js';

/**
 * Handles the playback of WebM files using the provided gateway API.
 *
 * @param {string} gatewayAccessUrl - The URL to access the gateway for video streaming.
 */
export async function handleWebm(gatewayAccessApi) {
  // Create element with correct spelling
  const shadowPlayer = /** @type {ShadowPlayer} */ (document.createElement('shadow-player'));

  // Append to DOM
  document.body.appendChild(shadowPlayer);

  // Wait for element to be initialized
  await customElements.whenDefined('shadow-player');

  // Wait for next microtask to ensure connectedCallback has run
  await new Promise(resolve => setTimeout(resolve, 0));

  // Now safe to call methods
  shadowPlayer.srcChange(gatewayAccessApi.sessionShadowingUrl(
    gatewayAccessApi.recordingInfo.files[0].fileName
  ));
  shadowPlayer.play();

  return shadowPlayer;
}
