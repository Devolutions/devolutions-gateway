import { ClientMessage, parseClientMessage, parseServerMessage, ServerMessage } from './protocol';

export class ServerWebSocket {
  ws: WebSocket;
  constructor(url: string) {
    this.ws = new WebSocket(url);
  }

  onopen(callback: (ev: Event) => unknown) {
    this.ws.onopen = callback;
  }

  onmessage(callback: (ev: ServerMessage) => unknown) {
    this.ws.onmessage = (ev) => {
      const reader = new FileReader();
      reader.onload = () => {
        const arrayBuffer = reader.result as ArrayBuffer;
        const serverResponse = parseServerMessage(arrayBuffer);
        callback(serverResponse);
      };

      reader.readAsArrayBuffer(ev.data);
    };
  }

  onclose(callback: (ev: CloseEvent) => unknown) {
    this.ws.onclose = callback;
  }

  onerror(callback: (ev: Event) => unknown) {
    this.ws.onerror = callback;
  }

  send<T extends ClientMessage>(data: T) {
    this.ws.send(parseClientMessage(data));
  }

  isClosed() {
    return this.ws.readyState === WebSocket.CLOSED;
  }
}
