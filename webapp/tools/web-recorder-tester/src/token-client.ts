// Mirrors recording-player-tester/src/api-client.ts, but requests a PUSH token (jet_rop: 'push')
// instead of a pull token. The dev token server (tools/tokengen, server mode) listens on :8080 and
// signs whatever jet_rop is passed; the Gateway's /jet/jrec/push endpoint requires jet_rop == Push.
const TOKEN_SERVER_BASE_URL = 'http://localhost:8080';

interface TokenResponse {
  token: string;
}

export async function requestPushToken(sessionId: string): Promise<string> {
  const response = await fetch(`${TOKEN_SERVER_BASE_URL}/jrec`, {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({jet_rop: 'push', jet_aid: sessionId}),
  });

  if (!response.ok) {
    throw new Error(`token server ${response.status}: ${await response.text()}`);
  }

  const data: TokenResponse = await response.json();
  return data.token;
}

// Builds the Gateway jrec push WebSocket URL. WebMRecorder appends `&fileType=webm`, so the URL must
// already carry a query parameter (the token) — hence the `?token=` here.
export function buildPushUrl(gatewayHost: string, sessionId: string, token: string): string {
  const scheme = gatewayHost.startsWith('https') || location.protocol === 'https:' ? 'wss' : 'ws';
  const host = gatewayHost.replace(/^https?:\/\//, '');
  return `${scheme}://${host}/jet/jrec/push/${sessionId}?token=${encodeURIComponent(token)}`;
}
