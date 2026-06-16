/** 'o' = terminal output, 'i' = keyboard input, 'r' = terminal resize */
export type AsciiCastV2EventCode = 'o' | 'i' | 'r';

export interface AsciiCastV2Header {
  version: 2;
  width: number;
  height: number;
  timestamp?: number;
  env?: { [key: string]: string };
}

export type AsciiCastV2Event = [number, AsciiCastV2EventCode, string];
export type AsciiCastV2Message = AsciiCastV2Header | AsciiCastV2Event;

export interface AsciiCastV2RecorderOptions {
  wsUrl: URL;
  cols: number;
  rows: number;
  env?: { [key: string]: string };
  terminal: {
    /** Register a callback for server output. May return an unsubscribe function. */
    onServerOutput: (callback: (data: string) => void) => (() => void) | undefined;
  };
}

export class AsciiCastV2Recorder {
  private startTime = 0;
  private websocket: QueuedWebSocket | null = null;
  private outputGeneration = 0;
  private unsubscribeOutput: (() => void) | null = null;

  constructor(private initConfig: AsciiCastV2RecorderOptions) {}

  // Resolves when the WebSocket opens and the asciicast header is sent.
  // Rejects with an error string on any failure.
  public start(): Promise<void> {
    this.internalStop();

    const { cols, rows, env, terminal } = this.initConfig;
    const wsUrl = new URL(this.initConfig.wsUrl);
    wsUrl.searchParams.set('fileType', 'asciicast');

    this.startTime = Date.now();
    const outputGeneration = ++this.outputGeneration;

    // Use definite assignment — Promise executor runs synchronously.
    let settle!: (error?: string) => void;
    let settled = false;

    const promise = new Promise<void>((resolve, reject) => {
      settle = (error?: string) => {
        if (settled) return;
        settled = true;
        if (error !== undefined) {
          reject(error);
        } else {
          resolve();
        }
      };
    });

    let connected = false;
    let websocket: QueuedWebSocket | null = null;

    const fail = (): void => {
      if (!websocket || this.websocket !== websocket) return;
      this.outputGeneration++;
      if (this.unsubscribeOutput) {
        this.unsubscribeOutput();
        this.unsubscribeOutput = null;
      }
      this.websocket = null;
      settle(connected ? 'ConnectionToTheRecordingServerLost' : 'UnableToConnectToTheRecordingServer');
    };

    try {
      websocket = new QueuedWebSocket(wsUrl.toString(), {
        onOpen: () => {
          if (this.websocket !== websocket) return;
          connected = true;
          settle();
        },
        onError: fail,
        onClose: fail,
      });
    } catch (error) {
      console.error('[AsciiCastV2Recorder] Failed to create WebSocket:', error);
      settle('UnableToConnectToTheRecordingServer');
      return promise;
    }
    this.websocket = websocket;

    // Header is queued until the WebSocket opens
    this.send({
      version: 2,
      timestamp: Math.floor(this.startTime / 1000),
      width: cols,
      height: rows,
      env,
    });

    try {
      const unsub = terminal.onServerOutput((data) => {
        if (this.outputGeneration !== outputGeneration || !this.websocket) {
          return;
        }
        // Convert \n to \r\n for proper terminal recording
        const normalizedData = data.replace(/\r?\n/g, '\r\n');
        this.onEvent('o', normalizedData);
      });
      this.unsubscribeOutput = typeof unsub === 'function' ? unsub : null;
    } catch (error) {
      console.error('[AsciiCastV2Recorder] Failed to subscribe to terminal output:', error);
      const ws = this.websocket;
      this.websocket = null;
      ws?.close();
      settle('UnableToStartRecording');
      return promise;
    }

    return promise;
  }

  public stop(): void {
    this.internalStop();
  }

  private internalStop(): void {
    this.outputGeneration++;
    if (this.unsubscribeOutput) {
      this.unsubscribeOutput();
      this.unsubscribeOutput = null;
    }
    // Null websocket before close() so the onClose callback ignores the event
    const ws = this.websocket;
    this.websocket = null;
    ws?.close();
  }

  private onEvent(eventCode: AsciiCastV2EventCode, data: string) {
    const elapsedSeconds = (Date.now() - this.startTime) / 1000;
    this.send([elapsedSeconds, eventCode, data]);
  }

  private send(data: AsciiCastV2Message) {
    this.websocket?.send(JSON.stringify(data) + '\n');
  }
}

interface QueuedWebSocketCallbacks {
  onOpen?: () => void;
  onClose?: () => void;
  onError?: () => void;
}

class QueuedWebSocket {
  private ws: WebSocket;
  private queue: string[] = [];
  private ready = false;

  constructor(url: string, callbacks?: QueuedWebSocketCallbacks) {
    this.ws = new WebSocket(url);
    this.ws.onopen = () => {
      this.ready = true;
      for (const data of this.queue) {
        this.ws.send(data);
      }
      this.queue = [];
      callbacks?.onOpen?.();
    };
    this.ws.onclose = () => {
      this.ready = false;
      this.queue = [];
      callbacks?.onClose?.();
    };
    this.ws.onerror = () => {
      callbacks?.onError?.();
    };
  }

  public send(data: string) {
    if (this.ws.readyState === WebSocket.CLOSING || this.ws.readyState === WebSocket.CLOSED) {
      return;
    }

    if (this.ready) {
      this.ws.send(data);
    } else {
      this.queue.push(data);
    }
  }

  public close() {
    this.ready = false;
    this.queue = [];

    // Only close if not already closing or closed
    if (this.ws.readyState !== WebSocket.CLOSING && this.ws.readyState !== WebSocket.CLOSED) {
      this.ws.close();
    }
  }
}
