import { ClientMessage, parseClientMessage, parseServerMessage, ServerMessage } from './protocol';

export class ServerWebSocket {
  private readonly socket: WebSocket;

  constructor(url: string) {
    this.socket = new WebSocket(url);
    this.socket.binaryType = 'arraybuffer';
  }

  onopen(callback: (event: Event) => void): void {
    this.socket.onopen = callback;
  }

  onmessage(callback: (message: ServerMessage) => Promise<void> | void, onFailure: (error: unknown) => void): void {
    this.socket.onmessage = (event) => {
      try {
        if (!(event.data instanceof ArrayBuffer)) {
          throw new Error('Server sent a non-binary message');
        }
        Promise.resolve(callback(parseServerMessage(event.data))).catch(onFailure);
      } catch (error) {
        onFailure(error);
      }
    };
  }

  onclose(callback: (event: CloseEvent) => void): void {
    this.socket.onclose = callback;
  }

  onerror(callback: (event: Event) => void): void {
    this.socket.onerror = callback;
  }

  send(message: ClientMessage): void {
    if (this.socket.readyState !== WebSocket.OPEN) {
      throw new Error('WebSocket is not open');
    }
    this.socket.send(parseClientMessage(message));
  }

  close(code: number, reason: string): void {
    this.socket.close(code, reason);
  }
}
