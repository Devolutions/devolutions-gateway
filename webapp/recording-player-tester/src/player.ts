import * as api from './api-client';

export interface OpenPlayerParams {
  recordingId: string;
  active: boolean;
  language?: string;
}

export function openPlayer(param: OpenPlayerParams | undefined = undefined) {
  if (param?.active) {
    openStreamingPlayer(param.recordingId, param.language);
  } else {
    openRecordingPlayer();
  }
}

async function openStreamingPlayer(uuid: string, language?: string) {
  const url = await api.getStreamingPlayerUrl(uuid, true);
  if (language) {
    url.searchParams.set('lang', language);
  }

  player().style.display = 'flex'; // Display the player div
  iframeContent().innerHTML = `
    <iframe src="${url}" frameborder="0" class="iframeContent" ></iframe>
  `;
}

function openRecordingPlayer() {
  const currentUrl = window.location.href;
  const url = new URL(currentUrl);
  // dummy, does not matter
  url.searchParams.set('token', '123456');
  url.searchParams.set('sessionId', '123456');
  url.pathname = '/jet/jrec/play';
  const finalUrl = url.toString();

  player().style.display = 'flex'; // Display the player div
  iframeContent().innerHTML = `
    <iframe src="${finalUrl}" frameborder="0" class="iframeContent" ></iframe>
  `;
}

export function closePlayer() {
  player().style.display = 'none'; // Hide the player div
  iframeContent().innerHTML = ''; // Remove the iframe
}

function iframeContent() {
  const iframeContent = player().querySelector('#frameWrapper');

  if (!iframeContent) {
    throw new Error('Iframe content not found');
  }
  return iframeContent;
}

function player() {
  const player = document.getElementById('player');
  if (!player) {
    throw new Error('Player not found');
  }
  return player;
}
