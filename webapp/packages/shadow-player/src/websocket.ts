import { ClientMessage, parseClientMessage, parseServerMessage, ServerMessage } from './protocol';

export class ServerWebSocket {
  private readonly socket: WebSocket;
  private pendingEvent = Promise.resolve();
  private closed = false;

  constructor(url: string) {
    this.socket = new WebSocket(url);
    this.socket.binaryType = 'arraybuffer';
  }

  onopen(callback: (event: Event) => void): void {
    this.socket.onopen = callback;
  }

  onmessage(callback: (message: ServerMessage) => Promise<void> | void, onFailure: (error: unknown) => void): void {
    this.socket.onmessage = (event) => {
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
    this.socket.onclose = (event) => {
      this.closed = true;
      this.enqueueEvent(() => callback(event));
    };
  }

  onerror(callback: (event: Event) => void): void {
    this.socket.onerror = (event) => this.enqueueEvent(() => callback(event));
  }

  send(message: ClientMessage): void {
    if (!this.isOpen()) {
      throw new Error('WebSocket is not open');
    }
    this.socket.send(parseClientMessage(message));
  }

  isOpen(): boolean {
    return !this.closed && this.socket.readyState === WebSocket.OPEN;
  }

  close(code: number, reason: string): void {
    this.socket.close(code, reason);
  }

  private enqueueEvent(callback: () => Promise<void> | void): void {
    const event = this.pendingEvent.then(callback);
    this.pendingEvent = event.catch(() => undefined);
  }
}
