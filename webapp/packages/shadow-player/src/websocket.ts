import { ClientMessage, parseClientMessage, parseServerMessage, ServerMessage } from './protocol';

/** WebSocket subprotocol that asks the Gateway for every output segment (shadow protocol v2). */
export const SHADOW_PROTOCOL_V2 = 'jrec-shadow.v2';

export type ShadowProtocolVersion = 'v1' | 'v2';

type ConnectionState = 'offering-v2' | 'fallback-v1' | 'open' | 'closing' | 'closed';

/**
 * Shadow WebSocket that offers shadow protocol v2 and falls back to v1 for older Gateways.
 *
 * Browsers fail the handshake when an offered subprotocol is not echoed, and report it like any other connection
 * failure. So when the first socket closes before it opens, it is retried once without the offer (shadow protocol v1).
 */
export class ServerWebSocket {
  private socket: WebSocket;
  private state: ConnectionState = 'offering-v2';
  private pendingEvent = Promise.resolve();

  private openCallback: ((event: Event) => void) | null = null;
  private messageCallback: ((event: MessageEvent) => void) | null = null;
  private closeCallback: ((event: CloseEvent) => void) | null = null;
  private errorCallback: ((event: Event) => void) | null = null;

  constructor(private readonly url: string) {
    this.socket = this.connect([SHADOW_PROTOCOL_V2]);
  }

  /**
   * The shadow protocol version the Gateway selected, once the socket is open.
   *
   * With v1, the Gateway sends one output segment and then ends the stream.
   * Segment-started messages are handled the same way with either version.
   */
  shadowProtocolVersion(): ShadowProtocolVersion {
    return this.socket.protocol === SHADOW_PROTOCOL_V2 ? 'v2' : 'v1';
  }

  onopen(callback: (event: Event) => void): void {
    this.openCallback = callback;
  }

  onmessage(callback: (message: ServerMessage) => Promise<void> | void, onFailure: (error: unknown) => void): void {
    this.messageCallback = (event) => {
      this.enqueueEvent(async () => {
        try {
          if (!(event.data instanceof ArrayBuffer)) {
            throw new Error('Server sent a non-binary message');
          }
          await callback(parseServerMessage(event.data));
        } catch (error) {
          onFailure(error);
        }
      });
    };
  }

  onclose(callback: (event: CloseEvent) => void): void {
    this.closeCallback = callback;
  }

  onerror(callback: (event: Event) => void): void {
    this.errorCallback = callback;
  }

  send(message: ClientMessage): void {
    if (!this.isOpen()) {
      throw new Error('WebSocket is not open');
    }
    this.socket.send(parseClientMessage(message));
  }

  isOpen(): boolean {
    return this.state === 'open' && this.socket.readyState === WebSocket.OPEN;
  }

  close(code: number, reason: string): void {
    if (this.state !== 'closed') {
      this.state = 'closing';
    }
    this.socket.close(code, reason);
  }

  private connect(protocols: string[]): WebSocket {
    const socket = new WebSocket(this.url, protocols);
    socket.binaryType = 'arraybuffer';
    socket.onopen = (event) => {
      this.state = 'open';
      this.openCallback?.(event);
    };
    socket.onmessage = (event) => this.messageCallback?.(event);
    socket.onerror = (event) => {
      if (this.state === 'offering-v2') {
        return;
      }
      const callback = this.errorCallback;
      this.enqueueEvent(() => callback?.(event));
    };
    socket.onclose = (event) => {
      if (this.state === 'offering-v2') {
        this.state = 'fallback-v1';
        this.socket = this.connect([]);
        return;
      }
      this.state = 'closed';
      const callback = this.closeCallback;
      this.enqueueEvent(() => callback?.(event));
    };
    return socket;
  }

  private enqueueEvent(callback: () => Promise<void> | void): void {
    const event = this.pendingEvent.then(callback);
    this.pendingEvent = event.catch(() => undefined);
  }
}
