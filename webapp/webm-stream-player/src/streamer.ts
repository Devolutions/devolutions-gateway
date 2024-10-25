import { ReactiveSourceBuffer } from './sourceBuffer';
import { ServerWebSocket } from './websocket';

export class WebmStreamPlayer extends HTMLElement {
  shadowRoot: ShadowRoot | null = null;
  _videoElement: HTMLVideoElement | null = null;
  _src: string | null = null;

  constructor() {
    super();
  }

  static get observedAttributes() {
    return ['src', 'autoplay', 'loop', 'muted', 'poster', 'preload', 'style', 'width', 'height', 'controls'];
  }

  attributeChangedCallback(name: string, _oldValue: string, newValue: string) {
    console.log('attributeChangedCallback', name, newValue);
    if (name === 'src') {
      this.srcChange(newValue);
      return;
    }

    if (Object.prototype.hasOwnProperty.call(this.videoElement, name)) {
      this.videoElement.setAttribute(name, newValue !== null ? newValue : '');
    }
  }

  connectedCallback() {
    this.init();
  }

  init() {
    this.shadowRoot = this.attachShadow({ mode: 'open' });
    const content = document.createElement('div');
    this.videoElement = document.createElement('video');
    this.videoElement.controls = true;
    content.appendChild(this.videoElement);
    this.shadowRoot.appendChild(content);
    this.syncAttributes();
  }

  syncAttributes() {
    for (const attr of WebmStreamPlayer.observedAttributes) {
      const value = this.getAttribute(attr);
      if (attr === 'src' && value !== null) {
        this.srcChange(value);
      }
      if (value !== null) {
        this.videoElement.setAttribute(attr, value);
      }
    }
  }

  private get videoElement() {
    return this._videoElement as HTMLVideoElement;
  }

  private set videoElement(value: HTMLVideoElement) {
    this._videoElement = value;
  }

  public srcChange(value: string) {
    const mediaSource = new MediaSource();
    this._src = value;
    this.videoElement.src = URL.createObjectURL(mediaSource);
    mediaSource.addEventListener('sourceopen', () => this.handleSourceOpen(mediaSource));
  }

  private async handleSourceOpen(mediaSource: MediaSource) {
    const websocket = new ServerWebSocket(this._src as string);
    let reactiveSourceBuffer: ReactiveSourceBuffer | null = null;
    let websocketClosed = false;

    websocket.onopen(() => {
      websocket.send({ type: 'start' });
      websocket.send({ type: 'pull' });
    });

    websocket.onmessage((ev) => {
      if (mediaSource.readyState === 'closed') {
        return;
      }
      if (ev.type === 'metadata') {
        const codec = ev.codec;
        reactiveSourceBuffer = new ReactiveSourceBuffer(mediaSource, codec, () => {
          websocket.send({ type: 'pull' });
        });
      }

      if (ev.type === 'chunk') {
        if (reactiveSourceBuffer) {
          reactiveSourceBuffer.appendBuffer(ev.data);
        }
      }
    });

    websocket.onclose(() => {
      websocketClosed = true;
      if (reactiveSourceBuffer) {
        mediaSource.endOfStream();
      }
    });

    websocket.onerror((ev) => {
      console.error('WebSocket error:', ev);
      if (mediaSource.readyState === 'open') {
        try {
          mediaSource.endOfStream();
        } catch (error) {
          console.error('endOfStream error:', error);
        }
      }
    });
  }
}

customElements.define('webm-stream-player', WebmStreamPlayer);
