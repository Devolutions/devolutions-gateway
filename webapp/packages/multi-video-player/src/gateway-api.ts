export interface GatewayRecordingFile {
  fileName: string;
  duration: number;
  startTime: number;
}

export interface GatewayRecordingFileConfig {
  sessionId: string;
  startTime: number;
  duration: number;
  files: GatewayRecordingFile[];
}

interface Session {
  id: string;
}

export class GatewayRecordingApi {
  constructor(
    public gatewayUrl: string,
    public sessionId: string,
    public token: string
  ) {}

  async fetchMetadata(): Promise<GatewayRecordingFileConfig> {
    const url = `${this.gatewayUrl}/jet/jrec/pull/${this.sessionId}/recording.json?token=${this.token}`;
    const response = await fetch(url);

    if (!response.ok) {
      throw new Error(`Failed to fetch recording metadata: ${response.status} ${response.statusText}`);
    }

    return await response.json();
  }

  getSegmentUrl(fileName: string): string {
    return `${this.gatewayUrl}/jet/jrec/pull/${this.sessionId}/${fileName}?token=${this.token}`;
  }

  getShadowUrl(): string {
    const wsUrl = this.gatewayUrl
      .replace('http://', 'ws://')
      .replace('https://', 'wss://');
    return `${wsUrl}/jet/jrec/shadow/${this.sessionId}?token=${this.token}`;
  }

  async isSessionActive(): Promise<boolean> {
    try {
      const url = `${this.gatewayUrl}/jet/sessions`;

      const response = await fetch(url, {
        headers: {
          'Authorization': `Bearer ${this.token}`
        }
      });

      if (!response.ok) {
        return false;
      }

      const sessions: Session[] = await response.json();
      const sessionExists = sessions.some((session) => session.id === this.sessionId);

      return sessionExists;
    } catch (error) {
      console.error('Error checking session activity:', error);
      return false;
    }
  }

  static fromPullUrl(pullUrl: string): GatewayRecordingApi {
    const url = new URL(pullUrl);
    const gatewayUrl = `${url.protocol}//${url.host}`;
    const sessionId = url.pathname.split('/jrec/pull/')[1].split('/')[0];
    const token = url.searchParams.get('token') || '';

    return new GatewayRecordingApi(gatewayUrl, sessionId, token);
  }
}
