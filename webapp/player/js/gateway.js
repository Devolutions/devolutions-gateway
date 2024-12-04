export class GatewayAccessApi {
  recordingInfo = null;
  constructor(gatewayAccessUrl, token, sessionId) {
    this.gatewayAccessUrl = gatewayAccessUrl;
    this.token = token;
    this.sessionId = sessionId;
  }

  static builder() {
    return new GatewayAccessApiBuilder();
  }

  async fetchRecordingInfo() {
    const response = await fetch(this.videoSrcInfoUrl());
    if (!response.ok) {
      throw new Error(`Request failed. Returned status of ${response.status}`);
    }
    this.recordingInfo = await response.json();
    return this.recordingInfo;
  }

  info() {
    return {
      gatewayAccessUrl: this.gatewayAccessUrl,
      token: this.token,
      sessionId: this.sessionId,
      recordingInfo: this.recordingInfo,
    };
  }

  videoSrcInfoUrl() {
    return `${this.gatewayAccessUrl}/jet/jrec/pull/${this.sessionId}/recording.json?token=${this.token}`;
  }

  staticRecordingUrl(fileName) {
    return `${this.gatewayAccessUrl}/jet/jrec/pull/${this.sessionId}/${fileName}?token=${this.token}`;
  }

  sessionShadowingUrl(fileName) {
    return `${this.gatewayAccessUrl.replace('http://', 'ws://').replace('https://', 'wss://')}/jet/jrec/shadow/${this.sessionId}/${fileName}?token=${this.token}`;
  }
}

class GatewayAccessApiBuilder {
  constructor() {
    this._gatewayAccessUrl = null;
    this._token = null;
    this._sessionId = null;
  }

  gatewayAccessUrl(gatewayAccessUrl) {
    this._gatewayAccessUrl = gatewayAccessUrl;
    return this;
  }

  token(token) {
    this._token = token;
    return this;
  }

  sessionId(sessionId) {
    this._sessionId = sessionId;
    return this;
  }

  build() {
    return new GatewayAccessApi(this._gatewayAccessUrl, this._token, this._sessionId);
  }
}
