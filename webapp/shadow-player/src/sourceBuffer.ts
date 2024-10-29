export class ReactiveSourceBuffer {
  sourceBuffer: SourceBuffer;
  bufferQueue: Uint8Array[] = [];
  isAppending = false;
  next = () => {};

  constructor(mediaSource: MediaSource, codec: string, next: () => void) {
    this.sourceBuffer = mediaSource.addSourceBuffer(`video/webm; codecs="${codec}"`);
    this.next = next;
    this.sourceBuffer.addEventListener('updateend', () => {
      this.tryAppendBuffer();
    });
  }

  appendBuffer(buffer: Uint8Array) {
    this.bufferQueue.push(buffer);
    this.tryAppendBuffer();
  }

  private tryAppendBuffer() {

    if (!this.isAppending && !this.sourceBuffer.updating && this.bufferQueue.length > 0) {
      this.isAppending = true;
      try {
        const buffer = this.bufferQueue.shift() as Uint8Array;
        this.sourceBuffer.appendBuffer(buffer);
      } catch (error) {
        console.error('appendBuffer error:', error);
      } finally {
        this.next();
        this.isAppending = false;
      }
    }
  }
}
