import type { StreamCodec } from './protocol';
import { ReactiveSourceBuffer } from './sourceBuffer';

export interface PlaybackClipMetadata {
  codec: StreamCodec;
  sequence: number;
}

export class PlaybackClip {
  readonly video = document.createElement('video');

  private readonly mediaSource = new MediaSource();
  private readonly objectUrl = URL.createObjectURL(this.mediaSource);
  private readonly opened: Promise<void>;
  private sourceBuffer: ReactiveSourceBuffer | null = null;
  private debug = false;
  private complete = false;
  private finishing: Promise<void> | null = null;
  private disposed = false;
  private cancelOpen!: () => void;

  constructor(readonly metadata: PlaybackClipMetadata) {
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
      this.cancelOpen = () => {
        cleanup();
        reject(new DOMException('stream interrupted', 'AbortError'));
      };

      this.mediaSource.addEventListener('sourceopen', onOpen);
      this.mediaSource.addEventListener('sourceclose', onClose);
    });
  }

  async open(): Promise<void> {
    this.ensureActive();
    await this.opened;
    this.ensureActive();
  }

  async append(data: Uint8Array): Promise<void> {
    await this.opened;
    this.ensureActive();
    if (this.complete || !this.sourceBuffer) {
      throw new Error('Cannot append to a completed clip');
    }
    await this.sourceBuffer.appendBuffer(data);
  }

  async finish(): Promise<void> {
    await this.opened;
    this.ensureActive();
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
      this.ensureActive();
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
    if (this.disposed) {
      return;
    }
    this.disposed = true;
    this.cancelOpen();
    this.sourceBuffer?.dispose();
    this.video.pause();
    this.video.removeAttribute('src');
    this.video.load();
    this.video.remove();
    URL.revokeObjectURL(this.objectUrl);
  }

  private ensureActive(): void {
    if (this.disposed) {
      throw new DOMException('stream interrupted', 'AbortError');
    }
  }
}
