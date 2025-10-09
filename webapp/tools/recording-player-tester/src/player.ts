import * as api from './api-client';

export interface OpenPlayerParams {
  recordingId: string;
  active: boolean;
  language?: string;
}

// Export these functions for use in React components
export function openPlayer(param: OpenPlayerParams | undefined = undefined) {
  if (param?.active) {
    return openStreamingPlayer(param.recordingId, param.language);
  }
  return openRecordingPlayer();
}

export async function openStreamingPlayer(uuid: string, language?: string) {
  const url = await api.getPlayerUrl({
    uid: uuid,
    active: true,
    lang: language || 'en',
  });
  if (language) {
    url.searchParams.set('lang', language);
  }
  return url.toString();
}

export function openRecordingPlayer() {
  const currentUrl = window.location.href;
  const url = new URL(currentUrl);
  // dummy, does not matter
  url.searchParams.set('token', '123456');
  url.searchParams.set('sessionId', '123456');
  url.pathname = '/jet/jrec/play';
  return url.toString();
}

export function closePlayer() {
  // This function is now handled by React component state
  return;
}
