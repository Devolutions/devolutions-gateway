export interface AssciiCastV2Header {
  version: 2;
  width: number;
  height: number;
  timestamp: number;
  env: {[key: string]: string};
}

export type AsciiCastV2EventCode = 'o' | 'i' | 'r';

export type AsciinCastV2Event = [number, 'o' | 'i' | 'r', string];
export type AsciiCastV2Event = AssciiCastV2Header | AsciinCastV2Event;

export class AsciiCastV2Recorder {
  private startTime = 0;
  private websocket: QueuedWebsocket | null = null;

  constructor(
    private initConfig: {
      wsUrl: URL;
      cols: number;
      rows: number;
      env: {[key: string]: string};
      terminal: {
        onServerOutput: (callback: (data: string) => void) => void;
      };
    },
  ) {}

  public start() {
    const {wsUrl, cols, rows, env, terminal} = this.initConfig;
    wsUrl.searchParams.set('fileType', 'asciicast');
    this.websocket = new QueuedWebsocket(wsUrl.toString());
    this.startTime = Date.now();
    this.send({
      version: 2,
      timestamp: this.startTime,
      width: cols,
      height: rows,
      env,
    });

    terminal.onServerOutput(data => {
      // Convert \n to \r\n for proper terminal recording
      const normalizedData = data.replace(/\r?\n/g, '\r\n');
      this.onEvent('o', normalizedData);
    });
  }

  public stop() {
    this.websocket?.close();
  }

  private onEvent(eventCode: AsciiCastV2EventCode, data: string) {
    const date = (Date.now() - this.startTime) / 1000;
    this.send([date, eventCode, data]);
  }

  private send(data: AsciiCastV2Event | AssciiCastV2Header) {
    this.websocket?.send(JSON.stringify(data) + '\n');
  }
}

class QueuedWebsocket {
  private ws: WebSocket;
  private queue: string[] = [];
  private ready = false;

  constructor(url: string) {
    this.ws = new WebSocket(url);
    this.ws.onopen = () => {
      this.ready = true;
      for (const data of this.queue) {
        this.ws.send(data);
      }
      this.queue = [];
    };
  }

  public send(data: string) {
    if (this.ready) {
      this.ws.send(data);
    } else {
      this.queue.push(data);
    }
  }

  public close() {
    // Only close if not already closing or closed
    if (this.ws.readyState !== WebSocket.CLOSING && this.ws.readyState !== WebSocket.CLOSED) {
      this.ws.close();
    }
  }
}
