import { ErrorMessage } from './protocol';
import { ReactiveSourceBuffer } from './sourceBuffer';
import styles from './streamer.css?inline';
import { ServerWebSocket } from './websocket';

export type ShadowPlayerError =
  | {
      type: 'websocket';
      inner: ErrorEvent;
    }
  | {
      type: 'protocol';
      inner: ErrorMessage;
    }
  | {
      type: 'session-not-found';
      message: string;
    };

type ShadowPlayerErrorCallback = (error: ShadowPlayerError) => void;

export class ShadowPlayer extends HTMLElement {
  shadowRoot: ShadowRoot | null = null;
  _videoElement: HTMLVideoElement | null = null;
  _src: string | null = null;
  _buffer: ReactiveSourceBuffer | null = null;
  onErrorCallback: ShadowPlayerErrorCallback | null = null;
  onEndCallback: (() => void) | null = null;
  debug = false;
  _container: HTMLDivElement | null = null;
  _replayButton: HTMLButtonElement | null = null;

  private websocket: ServerWebSocket | null = null;
  private isDisconnecting = false;

  static get observedAttributes() {
    return ['src', 'autoplay', 'loop', 'muted', 'poster', 'preload', 'style', 'width', 'height'];
  }

  setDebug(debug: boolean) {
    this.debug = debug;
    if (this._buffer) {
      this._buffer.setDebug(debug);
    }
  }

  onError(callback: ShadowPlayerErrorCallback) {
    this.onErrorCallback = callback;
  }

  onEnd(callback: () => void) {
    if (this._videoElement) {
      this._videoElement.controls = true;
    }
    this.onEndCallback = callback;
  }

  attributeChangedCallback(name: string, _oldValue: string, newValue: string) {
    if (name === 'src') {
      this.srcChange(newValue);
      return;
    }

    if (this._videoElement && Object.prototype.hasOwnProperty.call(this._videoElement, name)) {
      this._videoElement.setAttribute(name, newValue !== null ? newValue : '');
    }
  }

  connectedCallback() {
    this.init();
  }

  init() {
    this.shadowRoot = this.attachShadow({ mode: 'open' });

    // Add styles
    const style = document.createElement('style');
    style.textContent = styles;
    this.shadowRoot.appendChild(style);

    this._container = document.createElement('div');
    this._container.className = 'container';

    this.videoElement = document.createElement('video');
    // Set muted to true so that the browser security policy will allow autoplay.
    this.videoElement.muted = true;
    this._container.appendChild(this.videoElement);

    this._replayButton = document.createElement('button');
    this._replayButton.className = 'replay-button';
    this._replayButton.innerHTML = `
      <svg viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
        <path d="M12 5V1L7 6l5 5V7c3.31 0 6 2.69 6 6s-2.69 6-6 6-6-2.69-6-6H4c0 4.42 3.58 8 8 8s8-3.58 8-8-3.58-8-8-8z"/>
      </svg>
    `;
    this._replayButton.onclick = () => this.replay();
    this._container.appendChild(this._replayButton);

    this.shadowRoot.appendChild(this._container);
    this.syncAttributes();
  }

  syncAttributes() {
    for (const attr of ShadowPlayer.observedAttributes) {
      const value = this.getAttribute(attr);
      if (attr === 'src' && value !== null) {
        this.srcChange(value);
      }
      if (value !== null && this._videoElement) {
        this._videoElement.setAttribute(attr, value);
      }
    }
  }

  private get videoElement() {
    return this._videoElement as HTMLVideoElement;
  }

  private set videoElement(value: HTMLVideoElement) {
    this._videoElement = value;
  }

  public play() {
    if (this._videoElement) {
      this._videoElement.play();
    }
  }

  private replay() {
    if (this._replayButton) {
      this._replayButton.classList.remove('visible');
    }
    this._videoElement?.play();
  }

  public srcChange(value: string) {
    if (!this._videoElement) {
      return;
    }
    this.isDisconnecting = false;
    const mediaSource = new MediaSource();
    this._src = value;
    this._videoElement.src = URL.createObjectURL(mediaSource);
    mediaSource.addEventListener('sourceopen', () => {
      this.handleSourceOpen(mediaSource);
    });
  }

  private async handleSourceOpen(mediaSource: MediaSource) {
    this.websocket = new ServerWebSocket(this._src as string);
    let reactiveSourceBuffer: ReactiveSourceBuffer | null = null;

    this.websocket.onopen(() => {
      this.websocket!.send({ type: 'start' });
      this.websocket!.send({ type: 'pull' });

      this._videoElement?.addEventListener('ended', () => {
        this.showReplayButton();
      });
    });

    this.websocket.onmessage((ev) => {
      if (mediaSource.readyState === 'closed') {
        return;
      }
      if (ev.type === 'metadata') {
        const codec = ev.codec;
        reactiveSourceBuffer = new ReactiveSourceBuffer(mediaSource, codec, () => {
          this.websocket?.send({ type: 'pull' });
        });
        this._buffer = reactiveSourceBuffer;
      }

      if (ev.type === 'chunk') {
        if (!reactiveSourceBuffer) {
          return;
        }

        reactiveSourceBuffer.appendBuffer(ev.data);

        if (!this._videoElement) {
          return;
        }

        if (this.debug) {
          const v = this._videoElement;
          const buffered = v.buffered.length > 0
            ? `[${v.buffered.start(0).toFixed(2)}-${v.buffered.end(0).toFixed(2)}]`
            : '(empty)';
          console.log(
            `[shadow-player] chunk appended: duration=${v.duration.toFixed(2)} currentTime=${v.currentTime.toFixed(2)} buffered=${buffered} readyState=${v.readyState}`
          );
        }

        if (
          this._videoElement.buffered.length > 0 &&
          this._videoElement.buffered.end(0) - this._videoElement.currentTime > 5
        ) {
          this._videoElement.currentTime = this._videoElement.buffered.end(0);
        }
      }

      if (ev.type === 'error') {
        this.onErrorCallback?.({
          type: 'protocol',
          inner: ev,
        });
      }

      if (ev.type === 'end') {
        this.onEndCallback?.();
      }
    });

    this.websocket.onclose((ev) => {
      if (this.isDisconnecting) {
        this.websocket = null;
        return;
      }

      if (ev.code === 4001) {
        this.onErrorCallback?.({
          type: 'session-not-found',
          message: 'Recording session is no longer active',
        });
      }

      this.videoElement.controls = true;
      if (reactiveSourceBuffer && mediaSource.readyState === 'open') {
        try {
          if (this.debug && this._videoElement) {
            const v = this._videoElement;
            const buffered = v.buffered.length > 0
              ? `[${v.buffered.start(0).toFixed(2)}-${v.buffered.end(0).toFixed(2)}]`
              : '(empty)';
            console.log(
              `[shadow-player] BEFORE endOfStream: duration=${v.duration} currentTime=${v.currentTime.toFixed(2)} buffered=${buffered} mediaSource.readyState=${mediaSource.readyState}`
            );
          }
          mediaSource.endOfStream();
          if (this.debug && this._videoElement) {
            const v = this._videoElement;
            const buffered = v.buffered.length > 0
              ? `[${v.buffered.start(0).toFixed(2)}-${v.buffered.end(0).toFixed(2)}]`
              : '(empty)';
            console.log(
              `[shadow-player] AFTER endOfStream: duration=${v.duration} currentTime=${v.currentTime.toFixed(2)} buffered=${buffered} mediaSource.readyState=${mediaSource.readyState}`
            );
          }
        } catch (error) {
          if (this.debug) {
            console.error('[shadow-player] endOfStream error:', error);
          }
        }
      }
      this.websocket = null;
    });

    this.websocket.onerror((ev) => {
      if (this.isDisconnecting) {
        return;
      }

      this.onErrorCallback?.({
        type: 'websocket',
        inner: ev as unknown as ErrorEvent,
      });

      if (reactiveSourceBuffer && mediaSource.readyState === 'open') {
        try {
          mediaSource.endOfStream();
        } catch (error) {
          console.error('endOfStream error:', error);
        }
      }
    });
  }

  public downloadBUfferAsFile() {
    if (this._buffer && this.debug) {
      this._buffer.downloadBufferedFile();
    }
  }

  private showReplayButton() {
    if (this._replayButton) {
      this._replayButton.classList.add('visible');
    }
  }

  public disconnect(): void {
    this.isDisconnecting = true;

    if (this.websocket) {
      try {
        this.websocket.ws.close(1000, 'Component cleanup');
      } catch (error) {
        // Intentionally ignored: WebSocket may already be closed
      }
      this.websocket = null;
    }

    if (this._videoElement) {
      try {
        this._videoElement.pause();
        this._videoElement.src = '';
        this._videoElement.load();
      } catch (error) {
        // Intentionally ignored: Video element may already be in an invalid state
      }
    }
  }
}

customElements.define('shadow-player', ShadowPlayer);
