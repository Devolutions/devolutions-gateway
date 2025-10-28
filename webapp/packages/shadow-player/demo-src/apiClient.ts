// Base URL of the API
const TOKEN_SERVER_BASE_URL = 'http://localhost:8080';
const GATEWAY_BASE_URL = 'http://localhost:7171';

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
  try {
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
  } catch (error) {
    throw new Error(`Error: ${error.message}`);
  }
}

// Function to list recordings
export async function listRealtimeRecordings(): Promise<string[]> {
  const res = await requestScopeToken({ scope: 'gateway.recordings.read' });
  try {
    const response = await fetch(`${GATEWAY_BASE_URL}/jet/jrec/list?active=true`, {
      method: 'GET',
      headers: {
        Authorization: `Bearer ${res.token}`,
      },
    });

    if (!response.ok) {
      const errorResponse = await response.json();
      throw new Error(`Error ${response.status}: ${JSON.stringify(errorResponse)}`);
    }

    return await response.json();
  } catch (error: any) {
    throw new Error(`Error: ${error.message}`);
  }
}

interface PullTokenRequest extends CommonRequest {
  jet_rop: 'pull';
  jet_aid: string;
}

export async function requestPullToken(data: PullTokenRequest): Promise<TokenResponse> {
  try {
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
  } catch (error: any) {
    throw new Error(`Error: ${error.message}`);
  }
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
  try {
    const response = await fetch(`${GATEWAY_BASE_URL}/jet/jrec/pull/${uid}/recording.json`, {
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
  } catch (error: any) {
    throw new Error(`Error: ${error.message}`);
  }
}

export async function getStreamingWebsocketUrl(uid: string): Promise<string> {
  const token = await requestPullToken({ jet_rop: 'pull', jet_aid: uid });
  return `${GATEWAY_BASE_URL}/jet/jrec/shadow/${uid}?token=${token.token}`;
}
