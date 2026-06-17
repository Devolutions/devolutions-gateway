// Base URL of the API
const TOKEN_SERVER_BASE_URL = 'http://localhost:8080';
let GATEWAY_HOST = 'localhost:7171';

export function setGatewayHost(host: string) {
  GATEWAY_HOST = host;
}

// Common request fields
interface CommonRequest {
  validity_duration?: string;
  kid?: string;
  delegation_key_path?: string;
  jet_gw_id?: string;
}

// Response type
interface TokenResponse {
  token: string;
}

// Scope request interface
interface ScopeRequest extends CommonRequest {
  scope: string;
}

export async function requestScopeToken(data: ScopeRequest): Promise<TokenResponse> {
  const response = await fetch(`${TOKEN_SERVER_BASE_URL}/scope`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(data),
  });

  if (!response.ok) {
    const errorResponse = await response.json();
    throw new Error(`Error ${response.status}: ${JSON.stringify(errorResponse)}`);
  }

  return await response.json();
}

// Function to list recordings
export async function listRecordings({ active = false }): Promise<string[]> {
  if (!active) {
    console.log('Listing all recordings');
  }
  const res = await requestScopeToken({ scope: 'gateway.recordings.read' });
  const url = new URL(`http://${GATEWAY_HOST}/jet/jrec/list`);
  if (active) {
    url.searchParams.set('active', 'true');
  }
  const response = await fetch(url, {
    method: 'GET',
    headers: {
      Authorization: `Bearer ${res.token}`,
    },
  });

  if (!response.ok) {
    const errorResponse = await response.json();
    throw new Error(`Error ${response.status}: ${JSON.stringify(errorResponse)}`);
  }

  const result = await response.json();

  return result;
}

interface PullTokenRequest extends CommonRequest {
  jet_rop: 'pull';
  jet_aid: string;
}

export async function requestPullToken(data: PullTokenRequest): Promise<TokenResponse> {
  const response = await fetch(`${TOKEN_SERVER_BASE_URL}/jrec`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(data),
  });

  if (!response.ok) {
    const errorResponse = await response.json();
    throw new Error(`Error ${response.status}: ${JSON.stringify(errorResponse)}`);
  }

  return await response.json();
}

interface GetInfoFileResponse {
  duration: number;
  files: {
    fileName: string;
    startTime: number;
    duration: number;
  };
  sessionId: string;
  startTime: number;
}

export async function getInfoFile(uid: string): Promise<GetInfoFileResponse> {
  const pullFileToken = await requestPullToken({ jet_rop: 'pull', jet_aid: uid });
  const gatewaUrl = new_gateway_url();
  gatewaUrl.pathname = pull_path(uid, 'info.json');
  const response = await fetch(gatewaUrl, {
    method: 'GET',
    headers: {
      Authorization: `Bearer ${pullFileToken.token}`,
    },
  });

  if (!response.ok) {
    const errorResponse = await response.json();
    throw new Error(`Error ${response.status}: ${JSON.stringify(errorResponse)}`);
  }

  return await response.json();
}

export async function getPlayerUrl({
  uid,
  active,
  lang,
}: {
  uid: string;
  active: boolean;
  lang: string;
}): Promise<URL> {
  const token = await requestPullToken({ jet_rop: 'pull', jet_aid: uid });
  const url = new_gateway_url();
  url.pathname = play_path(uid);
  url.searchParams.set('token', token.token);
  url.searchParams.set('isActive', active.toString());
  url.searchParams.set('sessionId', uid);
  url.searchParams.set('lang', lang);
  return url;
}

export async function getRecordingUrl(uid: string): Promise<URL> {
  const token = await requestPullToken({ jet_rop: 'pull', jet_aid: uid });
  const url = new_gateway_url();
  url.pathname = pull_path(uid);
  url.searchParams.set('token', token.token);
  return url;
}

// Fetches a recording's start time (unix seconds) from its manifest. Powers the player tester's
// recency sort, since /jet/jrec/list only returns ids. Costs one pull token + one GET per recording.
export async function getRecordingStartTime(uid: string): Promise<number> {
  const token = await requestPullToken({ jet_rop: 'pull', jet_aid: uid });
  const url = new_gateway_url();
  url.pathname = `/jet/jrec/pull/${uid}/recording.json`;
  url.searchParams.set('token', token.token);
  const response = await fetch(url, { method: 'GET' });
  if (!response.ok) {
    throw new Error(`manifest ${response.status} for ${uid}`);
  }
  const data: { startTime?: number } = await response.json();
  return typeof data.startTime === 'number' ? data.startTime : 0;
}

const new_gateway_url = () => {
  return new URL(`http://${GATEWAY_HOST}`);
};

const pull_path = (uid: string, file: string | null = null) =>
  file ? `/jet/jrec/pull/${uid}` : `/jet/jrec/pull/${uid}/${file}`;
const play_path = (uid: string) => `/jet/jrec/play/${uid}`;
