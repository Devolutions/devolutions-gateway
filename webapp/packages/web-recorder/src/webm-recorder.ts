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
  private animationLoopHandle: ReturnType<typeof setInterval> | null = null;
  private isCleaningUp = false;

  private blobQueue: Blob[] = [];

  constructor(private readonly options: WebMRecorderOptions = {}) {}

  get isRecording() {
    return this._isRecording;
  }

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

  // Maintain continuous frame capture by drawing transparent pixels
  // This is necessary because:
  // 1. Remote connections often have static content with no visual updates
  // 2. Without regular frame updates, the MediaRecorder may not capture enough frames
  // 3. Insufficient frame capture can lead to:
  //    - Gaps in the recording
  //    - Black screens during streaming
  // Note: While setInterval is not ideal for frame timing, it provides
  // a practical solution for maintaining the stream
  private handleMediaRecorderStart(): void {
    const animationLoop = () => {
      const drawEmpty = () => {
        const ctx = this.canvas?.getContext('2d');
        if (!ctx) {
          return;
        }
        ctx.globalAlpha = 0;
        ctx.fillRect(0, 0, 1, 1);
      };

      return setInterval(drawEmpty, 1000 / CanvasStreamFPS);
    };
    this.animationLoopHandle = animationLoop();
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

    if (this.animationLoopHandle !== null) {
      clearInterval(this.animationLoopHandle);
      this.animationLoopHandle = null;
    }

    if (this.stream) {
      this.stream.getTracks().forEach(track => track.stop());
      this.stream = null;
    }

    this.mediaRecorder = null;
    this.ws = null;
    this.blobQueue.length = 0;
    // isCleaningUp flag is reset in stop() method to prevent race conditions
  }
}
