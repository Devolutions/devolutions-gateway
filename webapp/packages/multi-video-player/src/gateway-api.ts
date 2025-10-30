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

  static fromPullUrl(pullUrl: string): GatewayRecordingApi {
    const url = new URL(pullUrl);
    const pathParts = url.pathname.split('/pull/');
    const gatewayUrl = `${url.protocol}//${url.host}${pathParts[0]}`;
    const sessionId = pathParts[1].split('/')[0];
    const token = url.searchParams.get('token') || '';

    return new GatewayRecordingApi(gatewayUrl, sessionId, token);
  }
}
