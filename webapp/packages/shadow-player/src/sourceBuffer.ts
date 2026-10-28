export class ReactiveSourceBuffer {
  private readonly sourceBuffer: SourceBuffer;
  private readonly allBuffers: Blob[] = [];
  private pendingOperation = Promise.resolve();
  private debug = false;
  private disposed = false;
  private cancelAppend: (() => void) | null = null;

  constructor(mediaSource: MediaSource, codec: string) {
    this.sourceBuffer = mediaSource.addSourceBuffer(`video/webm; codecs="${codec}"`);
  }

  setDebug(debug: boolean): void {
    this.debug = debug;
  }

  appendBuffer(buffer: Uint8Array): Promise<void> {
    const operation = this.pendingOperation.then(() => this.append(buffer));
    this.pendingOperation = operation;
    return operation;
  }

  whenIdle(): Promise<void> {
    return this.pendingOperation;
  }

  dispose(): void {
    this.disposed = true;
    this.cancelAppend?.();
  }

  private async append(buffer: Uint8Array): Promise<void> {
    if (this.disposed) {
      throw new DOMException('stream interrupted', 'AbortError');
    }
    if (this.sourceBuffer.updating) {
      throw new Error('SourceBuffer is already updating');
    }

    if (this.debug) {
      this.allBuffers.push(new Blob([buffer], { type: 'video/webm' }));
    }

    await new Promise<void>((resolve, reject) => {
      const cleanup = () => {
        this.sourceBuffer.removeEventListener('updateend', onUpdateEnd);
        this.sourceBuffer.removeEventListener('error', onError);
        this.sourceBuffer.removeEventListener('abort', onAbort);
        this.cancelAppend = null;
      };
      const onUpdateEnd = () => {
        cleanup();
        resolve();
      };
      const onError = () => {
        cleanup();
        reject(new Error('SourceBuffer append failed'));
      };
      const onAbort = () => {
        cleanup();
        reject(new DOMException('stream interrupted', 'AbortError'));
      };

      this.cancelAppend = onAbort;
      this.sourceBuffer.addEventListener('updateend', onUpdateEnd);
      this.sourceBuffer.addEventListener('error', onError);
      this.sourceBuffer.addEventListener('abort', onAbort);
      try {
        this.sourceBuffer.appendBuffer(buffer);
      } catch (error) {
        cleanup();
        reject(error);
      }
    });
  }

  downloadBufferedFile(): void {
    const url = URL.createObjectURL(new Blob(this.allBuffers, { type: 'video/webm' }));
    const link = document.createElement('a');
    link.href = url;
    link.download = 'buffered-video.webm';
    document.body.appendChild(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(url);
  }
}
