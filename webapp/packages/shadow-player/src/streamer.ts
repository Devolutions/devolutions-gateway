import { PlaybackClip } from './playbackClip';
import {
  defaultPlaybackControlLabels,
  type PlaybackControlLabels,
  PlaybackControls,
  type PlaybackControlsAction,
} from './playbackControls';
import type { ErrorMessage, SegmentStartedMessage, ServerMessage } from './protocol';
import styles from './streamer.css?inline';
import { ServerWebSocket } from './websocket';

export type { PlaybackControlLabels } from './playbackControls';

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
  private muted = true;
  private volume = 1;
  private controls: PlaybackControls | null = null;
  private controlLabels = defaultPlaybackControlLabels;
  private readonly segmentStartTimes = new Map<PlaybackClip, number>();
  private readonly onFullscreenChange = () => this.renderPlayerControls();

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

  setControlLabels(labels: Partial<PlaybackControlLabels>): void {
    this.controlLabels = { ...this.controlLabels, ...labels };
    this.controls?.render({ type: 'labels', labels: this.controlLabels });
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
    if (name === 'controls') {
      return;
    }
    if (name === 'muted') {
      this.setMuted(newValue !== null);
      return;
    }
    for (const clip of this.clips) {
      this.applyVideoAttribute(clip.video, name, newValue);
    }
  }

  connectedCallback(): void {
    this.init();
    document.addEventListener('fullscreenchange', this.onFullscreenChange);
    const src = this.getAttribute('src');
    if (src !== null && !this.websocket) {
      this.srcChange(src);
    }
  }

  disconnectedCallback(): void {
    document.removeEventListener('fullscreenchange', this.onFullscreenChange);
    this.disconnect();
    this.controls?.dispose();
    this.controls = null;
  }

  init(): void {
    if (!this.root) {
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
    }

    if (!this.controls && this._container) {
      this.controls = new PlaybackControls(this._container);
      this.controls.onAction((action) => this.handleControlsAction(action));
      this.controls.render({ type: 'labels', labels: this.controlLabels });
    }
    this.shouldPlay = this.hasAttribute('autoplay');
    this.renderPlayerControls();
  }

  private handleControlsAction(action: PlaybackControlsAction): void {
    if (action.type === 'toggle-playback') {
      if (this.shouldPlay) {
        this.pause();
      } else {
        this.play();
      }
      return;
    }
    if (action.type === 'toggle-muted') {
      if (this.volume === 0) {
        this.setVolume(1);
      }
      this.setMuted(!this.muted);
      return;
    }
    if (action.type === 'set-volume') {
      this.setVolume(action.volume);
      this.setMuted(this.volume === 0);
      return;
    }
    if (action.type === 'seek') {
      const clip = this.clips[action.sequence];
      if (clip?.metadata.sequence === action.sequence) {
        this.seekToClip(clip, action.percentage);
      }
      return;
    }
    void this.toggleFullscreen().catch((error: unknown) => this.reportPlayerError(error));
  }

  private setMuted(muted: boolean): void {
    this.muted = muted;
    for (const clip of this.clips) {
      clip.video.muted = muted;
    }
    this.renderPlayerControls();
  }

  private setVolume(volume: number): void {
    this.volume = Math.max(0, Math.min(1, volume));
    for (const clip of this.clips) {
      clip.video.volume = this.volume;
    }
    this.renderPlayerControls();
  }

  private async toggleFullscreen(): Promise<void> {
    if (document.fullscreenElement === this) {
      await document.exitFullscreen();
    } else {
      await this.requestFullscreen();
    }
  }

  public play(): void {
    this.shouldPlay = true;
    this.renderPlayerControls();
    if (this.activeClip && !this.activeClip.video.ended) {
      void this.activeClip.video.play();
      return;
    }
    if (this.activateNextClip()) {
      return;
    }
    if (this.streamEnded && this.activeClip?.video.ended) {
      this.replay();
    }
  }

  public pause(): void {
    this.shouldPlay = false;
    this.activeClip?.video.pause();
    this.renderPlayerControls();
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
    this.renderAllSegments();
    this.renderPlayerControls();
  }

  public srcChange(value: string): void {
    this.closeSession();
    this._src = value;
    if (!this._container) {
      return;
    }

    this.streamEnded = false;
    this._replayButton?.classList.remove('visible');
    this.renderPlayerControls();
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
      this.sendRequest(websocket, 'pull');
      await this.startSegment(message);
      return;
    }
    if (message.type === 'chunk') {
      if (!this.receivingClip) {
        throw new Error('Received a chunk before a segment started');
      }
      this.sendRequest(websocket, 'pull');
      await this.receivingClip.append(message.data);
      return;
    }
    if (message.type === 'error') {
      this.onErrorCallback?.({ type: 'protocol', inner: message });
      return;
    }

    this.finishReceivingClip();
    this.streamEnded = true;
    this.renderPlayerControls();
    if (this.activeClip?.video.ended) {
      this.showReplayButton();
    }
    this.onEndCallback?.();
  }

  private async startSegment(metadata: SegmentStartedMessage): Promise<void> {
    if (metadata.sequence !== this.clips.length) {
      throw new Error(`Expected segment ${this.clips.length}, received ${metadata.sequence}`);
    }

    this.finishReceivingClip();
    const clip = new PlaybackClip(metadata);
    clip.setDebug(this.debug);
    this.configureVideo(clip);
    this.clips.push(clip);
    this.receivingClip = clip;
    this._container?.insertBefore(clip.video, this._replayButton);
    this.renderAllSegments();
    await clip.open();
  }

  private finishReceivingClip(): void {
    const clip = this.receivingClip;
    if (!clip) {
      return;
    }
    clip.finish();
    this.renderAllSegments();
  }

  private configureVideo(clip: PlaybackClip): void {
    const video = clip.video;
    video.className = 'clip';
    video.muted = this.muted;
    video.volume = this.volume;
    for (const attribute of ShadowPlayer.observedAttributes) {
      if (attribute !== 'src' && attribute !== 'controls' && attribute !== 'muted') {
        this.applyVideoAttribute(video, attribute, this.getAttribute(attribute));
      }
    }
    video.addEventListener(
      'loadeddata',
      () => {
        this.playableClips.add(clip);
        this.activateNextClip();
        this.renderAllSegments();
      },
      { once: true },
    );
    video.addEventListener('play', () => {
      if (this.activeClip === clip) {
        this.shouldPlay = true;
        this.renderPlayerControls();
      }
    });
    video.addEventListener('pause', () => {
      if (this.activeClip === clip && !video.ended) {
        this.shouldPlay = false;
        this.renderPlayerControls();
      }
    });
    video.addEventListener('ended', () => {
      if (this.activeClip !== clip) {
        return;
      }
      if (!this.activateNextClip() && this.streamEnded) {
        this.showReplayButton();
      }
      this.renderClipControls(clip);
      this.renderPlayerControls();
    });
    video.addEventListener('timeupdate', () => this.renderClipControls(clip));
    video.addEventListener('durationchange', () => this.renderAllSegments());
    video.addEventListener('progress', () => this.renderClipControls(clip));
    video.addEventListener('click', () => this.handleControlsAction({ type: 'toggle-playback' }));
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
      this.renderClipControls(clip);
      this.renderPlayerControls();
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
    if (previous) {
      this.renderClipControls(previous);
    }
    this.renderClipControls(clip);
    this.renderPlayerControls();
  }

  private seekToClip(clip: PlaybackClip, percentage: number): void {
    if (!this.playableClips.has(clip)) {
      return;
    }
    const duration = this.clipDuration(clip);
    if (duration <= 0) {
      return;
    }

    for (const laterClip of this.clips) {
      if (laterClip.metadata.sequence > clip.metadata.sequence && this.playableClips.has(laterClip)) {
        laterClip.video.currentTime = 0;
      }
    }
    clip.video.currentTime = duration * Math.max(0, Math.min(1, percentage));
    this._replayButton?.classList.remove('visible');
    this.activateClip(clip);
    this.renderAllSegments();
  }

  private clipDuration(clip: PlaybackClip): number {
    if (Number.isFinite(clip.video.duration) && clip.video.duration > 0) {
      return clip.video.duration;
    }
    const buffered = clip.video.buffered;
    return buffered.length > 0 ? buffered.end(buffered.length - 1) : 0;
  }

  private clipProgress(clip: PlaybackClip): number {
    if (!this.activeClip) {
      return 0;
    }
    if (clip.metadata.sequence < this.activeClip.metadata.sequence) {
      return 1;
    }
    if (clip !== this.activeClip) {
      return 0;
    }
    const duration = this.clipDuration(clip);
    return duration > 0 ? Math.max(0, Math.min(1, clip.video.currentTime / duration)) : 0;
  }

  private renderPlayerControls(): void {
    this.controls?.render({
      type: 'player',
      playing: this.shouldPlay,
      muted: this.muted,
      volume: this.volume,
      fullscreen: document.fullscreenElement === this,
    });
  }

  private renderClipControls(clip: PlaybackClip): void {
    const startTime = this.segmentStartTimes.get(clip);
    if (startTime === undefined) {
      return;
    }
    const duration = this.clipDuration(clip);
    const progress = this.clipProgress(clip);
    this.controls?.render({
      type: 'segment',
      sequence: clip.metadata.sequence,
      startTime,
      duration,
      currentTime: duration * progress,
      progress,
      playable: this.playableClips.has(clip),
    });
  }

  private renderAllSegments(): void {
    let startTime = 0;
    for (const clip of this.clips) {
      this.segmentStartTimes.set(clip, startTime);
      this.renderClipControls(clip);
      startTime += this.clipDuration(clip);
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
    this.renderPlayerControls();
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
    this.renderPlayerControls();
  }

  private reportPlayerError(value: unknown): void {
    const error = value instanceof Error ? value : new Error(String(value));
    this.onErrorCallback?.({ type: 'player', inner: error });
  }

  public downloadBUfferAsFile(): void {
    if (this.debug) {
      (this.receivingClip ?? this.activeClip)?.downloadBufferedFile();
    }
  }

  private showReplayButton(): void {
    this._replayButton?.classList.add('visible');
    this.renderPlayerControls();
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
    this.segmentStartTimes.clear();
    this.receivingClip = null;
    this.activeClip = null;
    this._videoElement = null;
    this.controls?.render({ type: 'reset' });
    this.renderPlayerControls();
  }
}

customElements.define('shadow-player', ShadowPlayer);
