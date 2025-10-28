import { GatewayAccessApi } from '../gateway';
import { handleCast } from './cast';
import { handleTrp } from './trp';
import { handleWebm } from './webm';

export const getPlayer = (fileType) => {
  const player = {
    play: (_: GatewayAccessApi) => {},
  };

  if (fileType === 'webm') {
    player.play = handleWebm;
  }

  if (fileType === 'trp') {
    player.play = handleTrp;
  }

  if (fileType === 'cast') {
    player.play = handleCast;
  }

  return player;
};
const originalFetch = window.fetch;
export function overrideFetch(objectUrl, content) {
  const originalFetch = window.fetch;
  window.fetch = (url) => {
    if (url === objectUrl) {
      return Promise.resolve(new Response(content));
    }
    return originalFetch(url);
  };
}

export function restoreFetch() {
  window.fetch = originalFetch;
}

export function loadFile(fileName) {
  return fetch(fileName)
    .then((response) => {
      if (!response.ok) {
        throw new Error(`Failed to load file ${fileName}: ${response.statusText}`);
      }
      return response.arrayBuffer();
    })
    .then((arrayBuffer) => new Uint8Array(arrayBuffer));
}
