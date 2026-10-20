export interface SessionEventsRecorderOptions {
  /** When the recorded media started, on this browser's clock: the `mediaStartTime` of the media recorder. */
  mediaStartTime: Date;
  /**
   * Language of the session as a BCP 47 tag, such as `fr-CA`.
   * The AI analysis writes its descriptions in it.
   */
  locale?: string;
}

/**
 * Pushes the session events log (`.slog`), the timeline of the session, next to the recording.
 * Gateway never changes it: its AI analysis is a separate log, written in the session language.
 *
 * It needs its own push URL, with a push token of its own: never the token of the media recorder.
 * Start it once the media recorder runs: Gateway refuses an events push before the recording starts, and a Gateway that
 * does not take events logs refuses only this push while the media push is connected.
 */
export class SessionEventsRecorder {
  private ws: WebSocket | null = null;
  private seq = 0;
  private settleStart: ((error?: string) => void) | null = null;

  /** Whether the events push is connected; it turns false when Gateway or the network ends it. */
  get isRecording(): boolean {
    return this.ws !== null;
  }

  /**
   * Resolves once `session.start` is sent, and rejects with an error string when the connection cannot open.
   * Gateway checks the session only once the connection is open, so a refusal such as an events push before the
   * recording, or a second events push for the session, resolves this and then ends the push: `isRecording` turns
   * false.
   * Stopping before the connection opens resolves it too.
   * Starting the same instance again continues `seq`; a new instance, such as after a page reload, starts again at 0.
   */
  start(pushUrl: string, options: SessionEventsRecorderOptions): Promise<void> {
    if (this.ws) {
      return Promise.reject('RecordingAlreadyInProgress');
    }

    let url: URL;
    let mediaStartTime: string;
    try {
      url = new URL(pushUrl);
      mediaStartTime = options.mediaStartTime.toISOString();
    } catch (error) {
      console.error('[SessionEventsRecorder] Invalid push URL or media start time:', error);
      return Promise.reject('UnableToStartRecording');
    }
    url.searchParams.set('fileType', 'slog');
    url.searchParams.set('artifact', 'events');

    return new Promise<void>((resolve, reject) => {
      this.settleStart = (error?: string) => {
        this.settleStart = null;
        if (error !== undefined) {
          reject(error);
        } else {
          resolve();
        }
      };

      let ws: WebSocket;
      try {
        ws = new WebSocket(url.toString());
      } catch (error) {
        console.error('[SessionEventsRecorder] Failed to create WebSocket:', error);
        this.settleStart('UnableToConnectToTheRecordingServer');
        return;
      }
      this.ws = ws;

      ws.onopen = () => {
        this.write({
          event: 'session.start',
          description: 'Session started',
          locale: options.locale,
          mediaStartTime,
        });
        this.settleStart?.();
      };
      ws.onerror = ws.onclose = () => {
        if (this.ws !== ws) return;
        this.ws = null;
        if (this.settleStart) {
          this.settleStart('UnableToConnectToTheRecordingServer');
        } else {
          console.warn('[SessionEventsRecorder] The events push ended unexpectedly');
        }
      };
    });
  }

  stop(): void {
    const ws = this.ws;
    if (!ws) {
      return;
    }

    this.write({ event: 'session.end', description: 'Session ended' });
    this.ws = null;
    ws.onopen = null;
    ws.onerror = null;
    ws.onclose = null;
    ws.close();
    // Stopping is intentional, so a start still pending resolves instead of rejecting.
    this.settleStart?.();
  }

  private write(entry: { event: string; description: string; [field: string]: unknown }): void {
    if (this.ws?.readyState !== WebSocket.OPEN) {
      return;
    }

    const line = { timestamp: new Date().toISOString(), seq: this.seq, ...entry };
    this.seq += 1;
    this.ws.send(`${JSON.stringify(line)}\n`);
  }
}
