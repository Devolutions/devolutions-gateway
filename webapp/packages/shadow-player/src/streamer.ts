import { PlaybackClip } from './playbackClip';
import type { ErrorMessage, SegmentStartedMessage, ServerMessage } from './protocol';
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
    }
  | {
      type: 'player';
      inner: Error;
    };

type ShadowPlayerErrorCallback = (error: ShadowPlayerError) => void;

export class ShadowPlayer extends HTMLElement {
  _videoElement: HTMLVideoElement | null = null;
  _src: string | null = null;
  onErrorCallback: ShadowPlayerErrorCallback | null = null;
  onEndCallback: (() => void) | null = null;
  debug = false;
  _container: HTMLDivElement | null = null;
  _replayButton: HTMLButtonElement | null = null;

  private root: ShadowRoot | null = null;
  private websocket: ServerWebSocket | null = null;
  private readonly clips: PlaybackClip[] = [];
  private readonly playableClips = new Set<PlaybackClip>();
  private receivingClip: PlaybackClip | null = null;
  private activeClip: PlaybackClip | null = null;
  private awaitingResponse = false;
  private shouldPlay = false;
  private streamEnded = false;

  static get observedAttributes(): string[] {
    return ['src', 'autoplay', 'controls', 'loop', 'muted', 'poster', 'preload', 'style', 'width', 'height'];
  }

  setDebug(debug: boolean): void {
    this.debug = debug;
    for (const clip of this.clips) {
      clip.setDebug(debug);
    }
  }

  onError(callback: ShadowPlayerErrorCallback): void {
    this.onErrorCallback = callback;
  }

  onEnd(callback: () => void): void {
    this.onEndCallback = callback;
  }

  attributeChangedCallback(name: string, _oldValue: string | null, newValue: string | null): void {
    if (name === 'src') {
      if (newValue === null) {
        this.disconnect();
        this._src = null;
      } else if (this._container) {
        this.srcChange(newValue);
      } else {
        this._src = newValue;
      }
      return;
    }

    if (name === 'autoplay' && newValue !== null) {
      this.shouldPlay = true;
    }
    for (const clip of this.clips) {
      this.applyVideoAttribute(clip.video, name, newValue);
    }
  }

  connectedCallback(): void {
    this.init();
    const src = this.getAttribute('src');
    if (src !== null && !this.websocket) {
      this.srcChange(src);
    }
  }

  disconnectedCallback(): void {
    this.disconnect();
  }

  init(): void {
    if (this.root) {
      return;
    }

    this.root = this.attachShadow({ mode: 'open' });
    const style = document.createElement('style');
    style.textContent = styles;
    this.root.appendChild(style);

    this._container = document.createElement('div');
    this._container.className = 'container';

    this._replayButton = document.createElement('button');
    this._replayButton.className = 'replay-button';
    this._replayButton.innerHTML = `
      <svg viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
        <path d="M12 5V1L7 6l5 5V7c3.31 0 6 2.69 6 6s-2.69 6-6 6-6-2.69-6-6H4c0 4.42 3.58 8 8 8s8-3.58 8-8-3.58-8-8-8z"/>
      </svg>
    `;
    this._replayButton.onclick = () => this.replay();
    this._container.appendChild(this._replayButton);
    this.root.appendChild(this._container);
    this.shouldPlay = this.hasAttribute('autoplay');
  }

  public play(): void {
    this.shouldPlay = true;
    if (this.activeClip) {
      void this.activeClip.video.play();
    } else {
      this.activateNextClip();
    }
  }

  private replay(): void {
    this._replayButton?.classList.remove('visible');
    const firstClip = this.clips[0];
    if (!firstClip) {
      return;
    }
    for (const clip of this.clips) {
      clip.video.currentTime = 0;
    }
    this.shouldPlay = true;
    this.activateClip(firstClip);
  }

  public srcChange(value: string): void {
    this.closeSession();
    this._src = value;
    if (!this._container) {
      return;
    }

    this.streamEnded = false;
    this._replayButton?.classList.remove('visible');
    const websocket = new ServerWebSocket(value);
    this.websocket = websocket;

    websocket.onopen(() => {
      if (this.websocket === websocket) {
        this.sendRequest(websocket, 'start');
      }
    });
    websocket.onmessage(
      async (message) => this.handleServerMessage(websocket, message),
      (error) => this.handlePlayerFailure(websocket, error),
    );
    websocket.onclose((event) => this.handleSocketClose(websocket, event));
    websocket.onerror((event) => this.handleSocketError(websocket, event));
  }

  private async handleServerMessage(websocket: ServerWebSocket, message: ServerMessage): Promise<void> {
    if (this.websocket !== websocket) {
      return;
    }
    if (!this.awaitingResponse) {
      throw new Error('Received a server message without a pending request');
    }
    this.awaitingResponse = false;

    if (message.type === 'segment-started') {
      await this.startSegment(message);
      this.sendRequest(websocket, 'pull');
      return;
    }
    if (message.type === 'chunk') {
      if (!this.receivingClip) {
        throw new Error('Received a chunk before a segment started');
      }
      await this.receivingClip.append(message.data);
      this.sendRequest(websocket, 'pull');
      return;
    }
    if (message.type === 'error') {
      this.onErrorCallback?.({ type: 'protocol', inner: message });
      return;
    }

    this.receivingClip?.finish();
    this.streamEnded = true;
    this.activeClip?.video.setAttribute('controls', '');
    if (this.activeClip?.video.ended) {
      this.showReplayButton();
    }
    this.onEndCallback?.();
  }

  private async startSegment(metadata: SegmentStartedMessage): Promise<void> {
    if (metadata.sequence !== this.clips.length) {
      throw new Error(`Expected segment ${this.clips.length}, received ${metadata.sequence}`);
    }

    this.receivingClip?.finish();
    const clip = new PlaybackClip(metadata);
    clip.setDebug(this.debug);
    this.configureVideo(clip);
    this.clips.push(clip);
    this.receivingClip = clip;
    this._container?.insertBefore(clip.video, this._replayButton);
    await clip.open();
  }

  private configureVideo(clip: PlaybackClip): void {
    const video = clip.video;
    video.className = 'clip';
    video.muted = true;
    for (const attribute of ShadowPlayer.observedAttributes) {
      if (attribute !== 'src') {
        this.applyVideoAttribute(video, attribute, this.getAttribute(attribute));
      }
    }
    video.addEventListener(
      'loadeddata',
      () => {
        this.playableClips.add(clip);
        this.activateNextClip();
      },
      { once: true },
    );
    video.addEventListener('play', () => {
      if (this.activeClip === clip) {
        this.shouldPlay = true;
      }
    });
    video.addEventListener('pause', () => {
      if (this.activeClip === clip && !video.ended) {
        this.shouldPlay = false;
      }
    });
    video.addEventListener('ended', () => {
      if (this.activeClip !== clip) {
        return;
      }
      if (!this.activateNextClip() && this.streamEnded) {
        this.showReplayButton();
      }
    });
  }

  private activateNextClip(): boolean {
    const sequence = this.activeClip ? this.activeClip.metadata.sequence + 1 : 0;
    const next = this.clips[sequence];
    if (!next || !this.playableClips.has(next)) {
      return false;
    }
    if (this.activeClip && !this.activeClip.video.ended) {
      return false;
    }
    this.activateClip(next);
    return true;
  }

  private activateClip(clip: PlaybackClip): void {
    if (this.activeClip === clip) {
      if (this.shouldPlay) {
        void clip.video.play();
      }
      return;
    }
    const previous = this.activeClip;
    this.activeClip = clip;
    if (previous) {
      previous.video.pause();
      previous.video.classList.remove('active');
    }
    this._videoElement = clip.video;
    clip.video.classList.add('active');
    if (this.shouldPlay) {
      void clip.video.play();
    }
  }

  private applyVideoAttribute(video: HTMLVideoElement, name: string, value: string | null): void {
    if (value === null) {
      video.removeAttribute(name);
    } else {
      video.setAttribute(name, value);
    }
  }

  private sendRequest(websocket: ServerWebSocket, type: 'start' | 'pull'): void {
    if (this.websocket !== websocket) {
      return;
    }
    if (this.awaitingResponse) {
      throw new Error('A stream request is already pending');
    }
    this.awaitingResponse = true;
    websocket.send({ type });
  }

  private handleSocketClose(websocket: ServerWebSocket, event: CloseEvent): void {
    if (this.websocket !== websocket) {
      return;
    }
    this.awaitingResponse = false;
    this.websocket = null;
    if (event.code === 4001) {
      this.onErrorCallback?.({
        type: 'session-not-found',
        message: 'Recording session is no longer active',
      });
    }
    this.activeClip?.video.setAttribute('controls', '');
  }

  private handleSocketError(websocket: ServerWebSocket, event: Event): void {
    if (this.websocket !== websocket) {
      return;
    }
    this.onErrorCallback?.({
      type: 'websocket',
      inner: event as ErrorEvent,
    });
  }

  private handlePlayerFailure(websocket: ServerWebSocket, value: unknown): void {
    if (this.websocket !== websocket) {
      return;
    }
    const error = value instanceof Error ? value : new Error(String(value));
    this.awaitingResponse = false;
    this.onErrorCallback?.({ type: 'player', inner: error });
    websocket.close(1000, 'Player failure');
    this.websocket = null;
    this.activeClip?.video.setAttribute('controls', '');
  }

  public downloadBUfferAsFile(): void {
    if (this.debug) {
      (this.receivingClip ?? this.activeClip)?.downloadBufferedFile();
    }
  }

  private showReplayButton(): void {
    this._replayButton?.classList.add('visible');
  }

  public disconnect(): void {
    this.closeSession();
  }

  private closeSession(): void {
    const websocket = this.websocket;
    this.websocket = null;
    this.awaitingResponse = false;
    websocket?.close(1000, 'Component cleanup');
    for (const clip of this.clips) {
      clip.dispose();
    }
    this.clips.length = 0;
    this.playableClips.clear();
    this.receivingClip = null;
    this.activeClip = null;
    this._videoElement = null;
  }
}

customElements.define('shadow-player', ShadowPlayer);
