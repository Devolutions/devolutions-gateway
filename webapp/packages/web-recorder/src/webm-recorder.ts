import {Observable, Subject} from 'rxjs';

const CanvasStreamFPS = 8;
const MediaRecorderRecordInterval = 10;

// Telemetry is reported through an optional injected hook so the library stays framework-agnostic;
// consumers (DVLS/Hub) map these events onto their own telemetry stack.
export type WebMRecorderTelemetryEvent = 'recording-initialized' | 'recording-stopped';

export interface WebMRecorderOptions {
  onTelemetry?: (event: WebMRecorderTelemetryEvent) => void;
}

export class WebMRecorder {
  private mediaRecorder: MediaRecorder | null = null;
  private ws: WebSocket | null = null;
  private subject = new Subject<void>();
  private _isRecording = false;
  private stream: MediaStream | null = null;
  private canvas: HTMLCanvasElement | null = null;
  private frameTimer: ReturnType<typeof setInterval> | null = null;
  private keepaliveTick = false;
  private isCleaningUp = false;

  private blobQueue: Blob[] = [];

  constructor(private readonly options: WebMRecorderOptions = {}) {}

  get isRecording() {
    return this._isRecording;
  }

  // Combined method for backward compatibility
  start(canvas: HTMLCanvasElement, recordingUrl: string): Observable<void> {
    // Prevent starting multiple recordings simultaneously
    if (this._isRecording || this.isCleaningUp) {
      console.warn('[WebMRecorder] Recording already in progress or cleaning up');
      return this.subject.asObservable();
    }

    // Create new Subject for each start cycle since completed Subjects cannot emit
    this.subject = new Subject<void>();
    this.canvas = canvas;
    if (!this.initializeCapture(canvas)) {
      console.error('Failed to initialize capture. Aborting recording.');
      throw new Error('UnableToStartRecording');
    }
    return this.startStreaming(recordingUrl);
  }

  stop(): void {
    if (this.isCleaningUp) {
      return; // Prevent circular cleanup calls
    }
    this.isCleaningUp = true;

    if (this._isRecording && this.mediaRecorder) {
      if (this.mediaRecorder.state !== 'inactive') {
        this.mediaRecorder.stop();
      }
    }

    if (this.ws && this.ws.readyState === WebSocket.OPEN) {
      this.ws.close();
    }

    this.cleanupResources();
    this.subject.complete();
    this.isCleaningUp = false; // Reset only after all cleanup is done

    this.options.onTelemetry?.('recording-stopped');
  }

  // Initialize canvas capture stream
  private initializeCapture(canvas: HTMLCanvasElement): boolean {
    if (!canvas) {
      console.error('IronRDP canvas not found');
      return false;
    }

    this.options.onTelemetry?.('recording-initialized');
    try {
      // Automatic capture, throttled to CanvasStreamFPS: the browser emits a frame whenever the canvas
      // is modified. (Manual mode — captureStream(0) + requestFrame() — does NOT feed MediaRecorder
      // reliably; it produces zero frames in Chromium, so we keep the canvas "dirty" instead.)
      this.stream = canvas.captureStream(CanvasStreamFPS);
      return true;
    } catch (error) {
      console.error('Failed to initialize canvas capture:', error);
      return false;
    }
  }

  // Start streaming to WebSocket
  private startStreaming(recordingUrl: string): Observable<void> {
    if (!this.stream) {
      console.error('No capture stream initialized');
      this.subject.error('lblCantViewRecording');
      this.subject.complete();
      return this.subject.asObservable();
    }

    this.initializeWebSocket(recordingUrl);
    return this.subject.asObservable();
  }

  private initializeWebSocket(recordingUrl: string): void {
    this.ws = new WebSocket(recordingUrl + '&fileType=webm');
    this.ws.onopen = this.handleWebSocketOpen.bind(this);
    this.ws.onerror = this.handleWebSocketError.bind(this);
    this.ws.onclose = this.handleWebSocketClose.bind(this);
  }

  private handleWebSocketOpen(): void {
    if (!this.stream) {
      this.subject.error('lblCantViewRecording');
      this.subject.complete();
      return;
    }

    const recorder = new MediaRecorder(this.stream, {mimeType: 'video/webm'});
    this.mediaRecorder = recorder;

    recorder.onstart = this.handleMediaRecorderStart.bind(this);
    recorder.ondataavailable = this.handleMediaRecorderDataAvailable.bind(this);
    recorder.onstop = this.handleMediaRecorderStop.bind(this);
    recorder.onerror = this.handleMediaRecorderError.bind(this);

    recorder.start(MediaRecorderRecordInterval);

    // Flush any queued blobs now that WebSocket is open
    if (this.blobQueue.length > 0) {
      for (const blob of this.blobQueue) {
        this.ws?.send(blob);
      }
      this.blobQueue.length = 0;
    }
  }

  private handleWebSocketClose(): void {
    if (!this._isRecording) {
      this.subject.error('UnableToConnectToTheRecordingServer');
    }
    this.subject.complete();
  }

  private handleWebSocketError(event: Event): void {
    console.error('[WebMRecorder] WebSocket error:', event);
    this.subject.error('ConnectionToTheRecordingServerLost');
    this.subject.complete();
    this.stop(); // Safe to call - stop() guards against circular calls
  }

  // captureStream only emits a frame when the canvas is *modified*. Remote desktops are often static,
  // so without this nudge the stream stalls (gaps / black screens). setInterval is not ideal for frame
  // timing but is a practical keepalive.
  private handleMediaRecorderStart(): void {
    this.frameTimer = setInterval(() => this.keepCanvasLive(), 1000 / CanvasStreamFPS);
  }

  // Nudge a single corner pixel with a *real* value change every tick. A zero-alpha / no-op draw is
  // elided by some engines' dirty-tracking (Edge 149 → empty WebM), so we alternate the pixel value.
  // save()/restore() keeps this from leaking state onto the canvas's shared 2D context.
  private keepCanvasLive(): void {
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
      this._isRecording = true;
      this.subject.next();
    }

    if (this.ws && this.ws.readyState === WebSocket.OPEN) {
      this.ws.send(event.data);
    } else {
      console.warn('[WebMRecorder] WebSocket not ready, buffering data.');
      this.blobQueue.push(event.data);
    }
  }

  private handleMediaRecorderStop(): void {
    if (!this._isRecording) return;

    if (this.ws && this.ws.readyState === WebSocket.OPEN) {
      this.ws.close();
    }

    this.cleanupResources();
    this.subject.complete();
  }

  private handleMediaRecorderError(error: Event): void {
    console.error('[WebMRecorder] MediaRecorder encountered an error:', error);
    this.subject.error('UnableToStartRecording');
    this.subject.complete();
    this.stop(); // Safe to call - stop() guards against circular calls
  }

  private cleanupResources(): void {
    this._isRecording = false;

    if (this.frameTimer !== null) {
      clearInterval(this.frameTimer);
      this.frameTimer = null;
    }

    if (this.stream) {
      this.stream.getTracks().forEach(track => track.stop());
      this.stream = null;
    }

    this.canvas = null;
    this.mediaRecorder = null;
    this.ws = null;
    this.blobQueue.length = 0;
    // isCleaningUp flag is reset in stop() method to prevent race conditions
  }
}
