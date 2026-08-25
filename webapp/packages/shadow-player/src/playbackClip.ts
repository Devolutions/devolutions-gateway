import type { SegmentStartedMessage } from './protocol';
import { ReactiveSourceBuffer } from './sourceBuffer';

export class PlaybackClip {
  readonly video = document.createElement('video');

  private readonly mediaSource = new MediaSource();
  private readonly objectUrl = URL.createObjectURL(this.mediaSource);
  private readonly opened: Promise<void>;
  private sourceBuffer: ReactiveSourceBuffer | null = null;
  private debug = false;
  private complete = false;
  private finishing: Promise<void> | null = null;

  constructor(readonly metadata: SegmentStartedMessage) {
    this.video.src = this.objectUrl;
    this.opened = new Promise<void>((resolve, reject) => {
      const cleanup = () => {
        this.mediaSource.removeEventListener('sourceopen', onOpen);
        this.mediaSource.removeEventListener('sourceclose', onClose);
      };
      const onOpen = () => {
        cleanup();
        try {
          this.sourceBuffer = new ReactiveSourceBuffer(this.mediaSource, metadata.codec);
          this.sourceBuffer.setDebug(this.debug);
          resolve();
        } catch (error) {
          reject(error);
        }
      };
      const onClose = () => {
        cleanup();
        reject(new Error('MediaSource closed before it opened'));
      };

      this.mediaSource.addEventListener('sourceopen', onOpen);
      this.mediaSource.addEventListener('sourceclose', onClose);
    });
  }

  async open(): Promise<void> {
    await this.opened;
  }

  async append(data: Uint8Array): Promise<void> {
    await this.opened;
    if (this.complete || !this.sourceBuffer) {
      throw new Error('Cannot append to a completed clip');
    }
    await this.sourceBuffer.appendBuffer(data);
  }

  async finish(): Promise<void> {
    await this.opened;
    if (this.finishing) {
      return this.finishing;
    }
    const sourceBuffer = this.sourceBuffer;
    if (this.complete || !sourceBuffer) {
      return;
    }

    this.complete = true;
    this.finishing = (async () => {
      await sourceBuffer.whenIdle();
      if (this.mediaSource.readyState !== 'open') {
        throw new Error('Cannot finish a MediaSource that is not open');
      }
      this.mediaSource.endOfStream();
    })();
    return this.finishing;
  }

  setDebug(debug: boolean): void {
    this.debug = debug;
    this.sourceBuffer?.setDebug(debug);
  }

  downloadBufferedFile(): void {
    this.sourceBuffer?.downloadBufferedFile();
  }

  dispose(): void {
    this.video.pause();
    this.video.removeAttribute('src');
    this.video.load();
    this.video.remove();
    URL.revokeObjectURL(this.objectUrl);
  }
}
