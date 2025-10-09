export class ReactiveSourceBuffer {
  sourceBuffer: SourceBuffer;
  bufferQueue: Uint8Array[] = [];
  isAppending = false;
  next = () => {};
  allBuffers: Blob[] = []; // Store all buffers for file creation
  debug = false;

  constructor(mediaSource: MediaSource, codec: string, next: () => void) {
    this.sourceBuffer = mediaSource.addSourceBuffer(`video/webm; codecs="${codec}"`);
    this.next = next;

    this.sourceBuffer.addEventListener('updateend', () => {
      this.tryAppendBuffer();
    });

    // Handle errors and trigger download of the file
    this.sourceBuffer.addEventListener('error', (event) => {
      this.logErrorDetails(event);
      this.downloadBufferedFile();
    });
  }

  setDebug(debug: boolean) {
    this.debug = debug;
  }

  appendBuffer(buffer: Uint8Array) {
    this.bufferQueue.push(buffer);
    if (this.debug) {
      this.allBuffers.push(new Blob([buffer], { type: 'video/webm' })); // Save each buffer
    }
    this.tryAppendBuffer();
  }

  private tryAppendBuffer() {
    if (!this.isAppending && !this.sourceBuffer.updating && this.bufferQueue.length > 0) {
      this.isAppending = true;
      try {
        const buffer = this.bufferQueue.shift() as Uint8Array;
        this.sourceBuffer.appendBuffer(buffer);
      } catch (error) {
        this.logErrorDetails(error);
      } finally {
        this.next();
        this.isAppending = false;
      }
    }
  }

  public downloadBufferedFile() {
    const completeBlob = new Blob(this.allBuffers, { type: 'video/webm' });
    const url = URL.createObjectURL(completeBlob);

    // Create a download link
    const link = document.createElement('a');
    link.href = url;
    link.download = 'buffered-video.webm';
    document.body.appendChild(link);
    link.click();

    // Cleanup
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
    console.log('Buffered file downloaded.');
  }

  private logErrorDetails(error: unknown) {
    console.error('Error encountered in ReactiveSourceBuffer:');

    // Log the error object with stack trace
    console.error('Error object:', error);

    // Log the state of the bufferQueue
    console.log('Current bufferQueue length:', this.bufferQueue.length);

    // Log the sourceBuffer state
    console.log('SourceBuffer updating:', this.sourceBuffer.updating);
    console.log('SourceBuffer buffered ranges:', this.getBufferedRanges());
  }

  private getBufferedRanges(): string {
    const ranges = this.sourceBuffer.buffered;
    let rangeStr = '';
    for (let i = 0; i < ranges.length; i++) {
      rangeStr += `[${ranges.start(i)} - ${ranges.end(i)}] `;
    }
    return rangeStr.trim();
  }
}
