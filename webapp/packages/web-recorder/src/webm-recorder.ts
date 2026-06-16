const CANVAS_STREAM_FPS = 8;
const MEDIA_RECORDER_INTERVAL_MS = 10;

// Telemetry is reported through an optional injected hook so the library stays framework-agnostic;
// consumers (DVLS/Hub) map these events onto their own telemetry stack.
export type WebMRecorderTelemetryEvent = 'recording-initialized' | 'recording-stopped';

export interface WebMRecorderOptions {
  onTelemetry?: (event: WebMRecorderTelemetryEvent) => void;
}

export class WebMRecorder {
  private mediaRecorder: MediaRecorder | null = null;
  private ws: WebSocket | null = null;
  private resolveStart: (() => void) | null = null;
  private rejectStart: ((reason: string) => void) | null = null;
  private _isRecording = false;
  private stream: MediaStream | null = null;
  private canvas: HTMLCanvasElement | null = null;
  private keepaliveRaf: number | null = null;
  private keepaliveTick = false;
  private isStarting = false;
  private isCleaningUp = false;
  private pendingError: string | null = null;

  constructor(private readonly options: WebMRecorderOptions = {}) {}

  get isRecording() {
    return this._isRecording;
  }

  // Resolves when the first data chunk is received (recording confirmed active).
  // Rejects with an error string on any failure.
  start(canvas: HTMLCanvasElement, recordingUrl: string): Promise<void> {
    if (this._isRecording || this.isStarting || this.isCleaningUp) {
      console.warn('[WebMRecorder] Recording already in progress or cleaning up');
      return Promise.reject('RecordingAlreadyInProgress');
    }

    const promise = new Promise<void>((resolve, reject) => {
      this.resolveStart = resolve;
      this.rejectStart = reject;
    });

    this.isStarting = true;
    this.canvas = canvas;
    if (!this.initializeCapture(canvas)) {
      this.isStarting = false;
      this.rejectStart?.('UnableToStartRecording');
      this.resolveStart = null;
      this.rejectStart = null;
      return promise;
    }
    this.startStreaming(recordingUrl);
    return promise;
  }

  stop(): void {
    if (this.isCleaningUp) {
      return;
    }
    this.isCleaningUp = true;
    this.stopKeepalive();

    if (this.mediaRecorder && this.mediaRecorder.state !== 'inactive') {
      this.mediaRecorder.stop();
      return;
    }

    // Resolve any pending start promise — stop() is an intentional user action.
    this.resolveStart?.();
    this.resolveStart = null;
    this.rejectStart = null;

    this.closeWebSocket();
    this.cleanupResources();
    this.fireTelemetry('recording-stopped');
  }

  // Initialize canvas capture stream
  private initializeCapture(canvas: HTMLCanvasElement): boolean {
    if (!canvas) {
      console.error('[WebMRecorder] Canvas element is null');
      return false;
    }

    try {
      // Automatic capture, throttled to CANVAS_STREAM_FPS: the browser emits a frame whenever the canvas
      // is modified. (Manual mode — captureStream(0) + requestFrame() — does NOT feed MediaRecorder
      // reliably; it produces zero frames in Chromium, so we keep the canvas "dirty" instead.)
      this.stream = canvas.captureStream(CANVAS_STREAM_FPS);
    } catch (error) {
      console.error('Failed to initialize canvas capture:', error);
      return false;
    }
    this.fireTelemetry('recording-initialized');
    return true;
  }

  private startStreaming(recordingUrl: string): void {
    if (!this.stream) {
      console.error('No capture stream initialized');
      this.isStarting = false;
      this.rejectStart?.('lblCantViewRecording');
      this.resolveStart = null;
      this.rejectStart = null;
      return;
    }

    try {
      this.initializeWebSocket(recordingUrl);
    } catch (error) {
      console.error('[WebMRecorder] Failed to create WebSocket:', error);
      this.isStarting = false;
      this.rejectStart?.('UnableToConnectToTheRecordingServer');
      this.resolveStart = null;
      this.rejectStart = null;
      this.cleanupResources();
    }
  }

  private initializeWebSocket(recordingUrl: string): void {
    const separator = recordingUrl.includes('?') ? '&' : '?';
    this.ws = new WebSocket(`${recordingUrl}${separator}fileType=webm`);
    this.ws.onopen = this.handleWebSocketOpen.bind(this);
    this.ws.onerror = this.handleWebSocketError.bind(this);
    this.ws.onclose = this.handleWebSocketClose.bind(this);
  }

  private handleWebSocketOpen(): void {
    if (!this.stream) {
      this.isStarting = false;
      this.rejectStart?.('lblCantViewRecording');
      this.resolveStart = null;
      this.rejectStart = null;
      this.closeWebSocket();
      this.cleanupResources();
      return;
    }

    try {
      const recorder = new MediaRecorder(this.stream, { mimeType: 'video/webm' });
      this.mediaRecorder = recorder;

      recorder.onstart = this.handleMediaRecorderStart.bind(this);
      recorder.ondataavailable = this.handleMediaRecorderDataAvailable.bind(this);
      recorder.onstop = this.handleMediaRecorderStop.bind(this);
      recorder.onerror = this.handleMediaRecorderError.bind(this);

      recorder.start(MEDIA_RECORDER_INTERVAL_MS);
    } catch (error) {
      console.error('[WebMRecorder] Failed to start MediaRecorder:', error);
      this.isStarting = false;
      this.rejectStart?.('UnableToStartRecording');
      this.resolveStart = null;
      this.rejectStart = null;
      this.closeWebSocket();
      this.cleanupResources();
    }
  }

  private handleWebSocketClose(event: CloseEvent): void {
    if (this.isCleaningUp) {
      return;
    }

    this.isCleaningUp = true;
    this.stopKeepalive();

    const wasRecording = this._isRecording || (this.mediaRecorder !== null && this.mediaRecorder.state !== 'inactive');
    const errorCode = wasRecording ? 'ConnectionToTheRecordingServerLost' : 'UnableToConnectToTheRecordingServer';

    if (this.mediaRecorder && this.mediaRecorder.state !== 'inactive') {
      // Defer rejection until handleMediaRecorderStop so cleanup runs first.
      this.pendingError = errorCode;
      this.mediaRecorder.stop();
      return;
    }

    console.warn('[WebMRecorder] WebSocket closed unexpectedly (no active recorder):', event);
    this.rejectStart?.(errorCode);
    this.resolveStart = null;
    this.rejectStart = null;
    this.cleanupResources();
  }

  private handleWebSocketError(event: Event): void {
    console.error('[WebMRecorder] WebSocket error:', event);
    if (this.isCleaningUp) return;
    this.isCleaningUp = true;
    this.stopKeepalive();

    const wasRecording = this._isRecording || (this.mediaRecorder !== null && this.mediaRecorder.state !== 'inactive');
    const errorCode = wasRecording ? 'ConnectionToTheRecordingServerLost' : 'UnableToConnectToTheRecordingServer';

    if (this.mediaRecorder && this.mediaRecorder.state !== 'inactive') {
      this.pendingError = errorCode;
      this.mediaRecorder.stop();
      return;
    }

    this.rejectStart?.(errorCode);
    this.resolveStart = null;
    this.rejectStart = null;
    this.closeWebSocket();
    this.cleanupResources();
  }

  // Browser captureStream implementations are unreliable for static or sparsely updated canvases.
  // Drive the keepalive from rAF so the nudge is aligned with the rendering pipeline, and make a real
  // change each frame so captureStream always has fresh canvas content to sample.
  private handleMediaRecorderStart(): void {
    const tick = (): void => {
      this.nudgeCanvas();
      this.keepaliveRaf = requestAnimationFrame(tick);
    };
    this.keepaliveRaf = requestAnimationFrame(tick);
  }

  // Nudge a single corner pixel with a *real* value change. A zero-alpha / no-op draw is elided by
  // some engines' dirty-tracking (Edge 149 → empty WebM), so we alternate the pixel value. captureStream
  // throttles the actual capture to CANVAS_STREAM_FPS regardless of the rAF rate. save()/restore() keeps
  // this from leaking state onto the canvas's shared 2D context.
  private nudgeCanvas(): void {
    const ctx = this.canvas?.getContext('2d');
    if (!ctx) {
      return;
    }
    ctx.save();
    ctx.globalAlpha = 1;
    ctx.fillStyle = this.keepaliveTick ? '#000000' : '#000001';
    ctx.fillRect(0, 0, 1, 1);
    ctx.restore();
    this.keepaliveTick = !this.keepaliveTick;
  }

  private handleMediaRecorderDataAvailable(event: BlobEvent): void {
    if (!event.data || event.data.size === 0) return;

    if (!this._isRecording) {
      this.isStarting = false;
      this._isRecording = true;
      // Resolve the start promise — first data confirms recording is active.
      this.resolveStart?.();
      this.resolveStart = null;
      this.rejectStart = null;
    }

    if (this.ws && this.ws.readyState === WebSocket.OPEN) {
      this.ws.send(event.data);
    }
  }

  private handleMediaRecorderStop(): void {
    this.closeWebSocket();
    const error = this.pendingError; // read before cleanupResources() clears it
    // Settle the start promise before cleanup resets isCleaningUp.
    if (error) {
      // Pre-start failure — recording was never confirmed to the consumer.
      this.rejectStart?.(error);
    } else {
      // Normal stop initiated by stop() — resolveStart is already null if recording
      // was confirmed, or resolveStart needs settling if stop() was called before first data.
      this.resolveStart?.();
    }
    this.resolveStart = null;
    this.rejectStart = null;
    this.cleanupResources(); // resets isCleaningUp = false
    if (!error) {
      this.fireTelemetry('recording-stopped');
    }
  }

  private handleMediaRecorderError(error: Event): void {
    console.error('[WebMRecorder] MediaRecorder encountered an error:', error);
    if (this.isCleaningUp) return;
    this.isCleaningUp = true;
    this.stopKeepalive();
    // Defer rejection until handleMediaRecorderStop so cleanup completes first.
    this.pendingError = 'UnableToStartRecording';
  }

  private fireTelemetry(event: WebMRecorderTelemetryEvent): void {
    try {
      this.options.onTelemetry?.(event);
    } catch (e) {
      console.warn('[WebMRecorder] onTelemetry hook threw:', e);
    }
  }

  private cleanupResources(): void {
    this._isRecording = false;
    this.isStarting = false;
    this.stopKeepalive();

    if (this.ws) {
      this.ws.onopen = null;
      this.ws.onerror = null;
      this.ws.onclose = null;
    }

    if (this.stream) {
      this.stream.getTracks().forEach((track) => track.stop());
      this.stream = null;
    }

    this.canvas = null;
    if (this.mediaRecorder) {
      this.mediaRecorder.onstart = null;
      this.mediaRecorder.ondataavailable = null;
      this.mediaRecorder.onstop = null;
      this.mediaRecorder.onerror = null;
    }
    this.mediaRecorder = null;
    this.ws = null;
    this.resolveStart = null;
    this.rejectStart = null;
    this.pendingError = null;
    this.isCleaningUp = false;
  }

  private stopKeepalive(): void {
    if (this.keepaliveRaf !== null) {
      cancelAnimationFrame(this.keepaliveRaf);
      this.keepaliveRaf = null;
    }
  }

  private closeWebSocket(): void {
    if (!this.ws) {
      return;
    }

    this.ws.onclose = null;
    this.ws.onerror = null;

    if (this.ws.readyState === WebSocket.OPEN || this.ws.readyState === WebSocket.CONNECTING) {
      this.ws.close();
    }
  }
}
