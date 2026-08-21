import styles from './playbackControls.css?inline';

export interface PlaybackControlLabels {
  play: string;
  pause: string;
  mute: string;
  unmute: string;
  volume: string;
  timeline: string;
  fullscreen: string;
  exitFullscreen: string;
  clip: string;
}

export const defaultPlaybackControlLabels: PlaybackControlLabels = {
  play: 'Play',
  pause: 'Pause',
  mute: 'Mute',
  unmute: 'Unmute',
  volume: 'Volume',
  timeline: 'Recording timeline',
  fullscreen: 'Fullscreen',
  exitFullscreen: 'Exit fullscreen',
  clip: 'Clip',
};

export type PlaybackControlsAction =
  | { type: 'toggle-playback' }
  | { type: 'toggle-muted' }
  | { type: 'set-volume'; volume: number }
  | { type: 'seek'; sequence: number; percentage: number }
  | { type: 'toggle-fullscreen' };

export type PlaybackControlsSnapshot =
  | {
      type: 'player';
      playing: boolean;
      muted: boolean;
      volume: number;
      fullscreen: boolean;
    }
  | {
      type: 'segment';
      sequence: number;
      startTime: number;
      duration: number;
      currentTime: number;
      progress: number;
      playable: boolean;
    }
  | { type: 'labels'; labels: PlaybackControlLabels }
  | { type: 'reset' };

const icons = {
  play: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M8 5v14l11-7z"/></svg>',
  pause: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M6 5h4v14H6zm8 0h4v14h-4z"/></svg>',
  muted:
    '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M4 9v6h4l5 4V5L8 9H4zm11.5 3 2.25 2.25 1.5-1.5L17 10.5l2.25-2.25-1.5-1.5L15.5 9 13.25 6.75l-1.5 1.5L14 10.5l-2.25 2.25 1.5 1.5z"/></svg>',
  volume:
    '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M3 9v6h4l5 4V5L7 9H3zm11.5 3a3.5 3.5 0 0 0-2-3.16v6.32a3.5 3.5 0 0 0 2-3.16zm-2-7.18v2.06a5.5 5.5 0 0 1 0 10.24v2.06a7.5 7.5 0 0 0 0-14.36z"/></svg>',
  fullscreen:
    '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M5 5h5V3H3v7h2V5zm9-2v2h5v5h2V3h-7zm5 16h-5v2h7v-7h-2v5zM5 14H3v7h7v-2H5v-5z"/></svg>',
  exitFullscreen:
    '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M7 14H3v2h2v2h2v-4zm0-4V6H5v2H3v2h4zm10 8h2v-2h2v-2h-4v4zm0-12v4h4V8h-2V6h-2z"/></svg>',
} as const;

interface SegmentView {
  state: Extract<PlaybackControlsSnapshot, { type: 'segment' }>;
  track: HTMLDivElement;
  fill: HTMLDivElement;
  tooltip: HTMLSpanElement;
}

export class PlaybackControls {
  private readonly style: HTMLStyleElement;
  private readonly controlBar: HTMLDivElement;
  private readonly playButton: HTMLButtonElement;
  private readonly muteButton: HTMLButtonElement;
  private readonly volumeInput: HTMLInputElement;
  private readonly timeline: HTMLDivElement;
  private readonly fullscreenButton: HTMLButtonElement;
  private readonly segments = new Map<number, SegmentView>();
  private labels = defaultPlaybackControlLabels;
  private player = {
    playing: false,
    muted: true,
    volume: 1,
    fullscreen: false,
  };
  private actionCallback: ((action: PlaybackControlsAction) => void) | null = null;

  constructor(container: HTMLElement) {
    this.style = document.createElement('style');
    this.style.textContent = styles;
    container.appendChild(this.style);

    this.controlBar = document.createElement('div');
    this.controlBar.className = 'control-bar';

    this.playButton = this.createControlButton();
    this.playButton.addEventListener('click', () => this.emit({ type: 'toggle-playback' }));
    this.controlBar.appendChild(this.playButton);

    const volumeControl = document.createElement('div');
    volumeControl.className = 'volume-control';
    this.muteButton = this.createControlButton();
    this.muteButton.addEventListener('click', () => this.emit({ type: 'toggle-muted' }));
    volumeControl.appendChild(this.muteButton);

    this.volumeInput = document.createElement('input');
    this.volumeInput.className = 'volume-input';
    this.volumeInput.type = 'range';
    this.volumeInput.min = '0';
    this.volumeInput.max = '1';
    this.volumeInput.step = '0.05';
    this.volumeInput.addEventListener('input', () => {
      this.emit({ type: 'set-volume', volume: Number.parseFloat(this.volumeInput.value) });
    });
    volumeControl.appendChild(this.volumeInput);
    this.controlBar.appendChild(volumeControl);

    this.timeline = document.createElement('div');
    this.timeline.className = 'timeline';
    this.timeline.setAttribute('role', 'group');
    this.controlBar.appendChild(this.timeline);

    this.fullscreenButton = this.createControlButton();
    this.fullscreenButton.addEventListener('click', () => this.emit({ type: 'toggle-fullscreen' }));
    this.controlBar.appendChild(this.fullscreenButton);

    container.appendChild(this.controlBar);
    this.render({ type: 'labels', labels: this.labels });
    this.render({ type: 'player', ...this.player });
  }

  onAction(callback: (action: PlaybackControlsAction) => void): void {
    this.actionCallback = callback;
  }

  render(snapshot: PlaybackControlsSnapshot): void {
    if (snapshot.type === 'player') {
      this.renderPlayer(snapshot);
      return;
    }
    if (snapshot.type === 'segment') {
      this.renderSegment(snapshot);
      return;
    }
    if (snapshot.type === 'labels') {
      this.renderLabels(snapshot.labels);
      return;
    }
    this.segments.clear();
    this.timeline.replaceChildren();
  }

  dispose(): void {
    this.actionCallback = null;
    this.segments.clear();
    this.controlBar.remove();
    this.style.remove();
  }

  private createControlButton(): HTMLButtonElement {
    const button = document.createElement('button');
    button.className = 'control-button';
    button.type = 'button';
    return button;
  }

  private renderPlayer(snapshot: Extract<PlaybackControlsSnapshot, { type: 'player' }>): void {
    this.player = snapshot;
    this.setButton(
      this.playButton,
      snapshot.playing ? this.labels.pause : this.labels.play,
      snapshot.playing ? icons.pause : icons.play,
    );
    const silent = snapshot.muted || snapshot.volume === 0;
    this.setButton(
      this.muteButton,
      silent ? this.labels.unmute : this.labels.mute,
      silent ? icons.muted : icons.volume,
    );
    this.volumeInput.value = String(snapshot.volume);
    this.setButton(
      this.fullscreenButton,
      snapshot.fullscreen ? this.labels.exitFullscreen : this.labels.fullscreen,
      snapshot.fullscreen ? icons.exitFullscreen : icons.fullscreen,
    );
  }

  private renderLabels(labels: PlaybackControlLabels): void {
    this.labels = labels;
    this.volumeInput.setAttribute('aria-label', labels.volume);
    this.timeline.setAttribute('aria-label', labels.timeline);
    this.render({ type: 'player', ...this.player });
    for (const view of this.segments.values()) {
      this.renderSegment(view.state);
    }
  }

  private renderSegment(snapshot: Extract<PlaybackControlsSnapshot, { type: 'segment' }>): void {
    const view = this.segments.get(snapshot.sequence) ?? this.createSegment(snapshot);
    view.state = snapshot;
    view.track.style.flexGrow = String(Math.max(1, snapshot.duration));
    view.track.setAttribute('aria-label', `${this.labels.clip} ${snapshot.sequence + 1}`);
    view.track.setAttribute('aria-disabled', String(!snapshot.playable));
    view.track.setAttribute('aria-valuenow', String(Math.round(snapshot.progress * 100)));
    view.track.setAttribute('aria-valuetext', formatTime(snapshot.startTime + snapshot.currentTime));
    view.fill.style.width = `${snapshot.progress * 100}%`;
  }

  private createSegment(snapshot: Extract<PlaybackControlsSnapshot, { type: 'segment' }>): SegmentView {
    const track = document.createElement('div');
    track.className = 'timeline-segment';
    track.tabIndex = 0;
    track.setAttribute('role', 'slider');
    track.setAttribute('aria-valuemin', '0');
    track.setAttribute('aria-valuemax', '100');

    const fill = document.createElement('div');
    fill.className = 'timeline-progress';
    track.appendChild(fill);

    const tooltip = document.createElement('span');
    tooltip.className = 'time-tooltip';
    track.appendChild(tooltip);

    const view = { state: snapshot, track, fill, tooltip };
    track.addEventListener('click', (event) => this.seekFromPointer(view, event));
    track.addEventListener('pointermove', (event) => this.renderTooltip(view, event));
    track.addEventListener('keydown', (event) => this.seekFromKeyboard(view, event));

    this.segments.set(snapshot.sequence, view);
    this.timeline.appendChild(track);
    return view;
  }

  private seekFromPointer(view: SegmentView, event: MouseEvent | PointerEvent): void {
    if (!view.state.playable) {
      return;
    }
    this.emit({
      type: 'seek',
      sequence: view.state.sequence,
      percentage: pointerPercentage(view.track, event),
    });
  }

  private renderTooltip(view: SegmentView, event: PointerEvent): void {
    const percentage = pointerPercentage(view.track, event);
    view.tooltip.style.left = `${percentage * 100}%`;
    view.tooltip.textContent = formatTime(view.state.startTime + view.state.duration * percentage);
  }

  private seekFromKeyboard(view: SegmentView, event: KeyboardEvent): void {
    if (!view.state.playable) {
      return;
    }
    let percentage: number | null = null;
    if (event.key === 'ArrowLeft' || event.key === 'ArrowDown') {
      percentage = view.state.progress - 0.05;
    } else if (event.key === 'ArrowRight' || event.key === 'ArrowUp') {
      percentage = view.state.progress + 0.05;
    } else if (event.key === 'Home') {
      percentage = 0;
    } else if (event.key === 'End') {
      percentage = 1;
    }
    if (percentage === null) {
      return;
    }
    event.preventDefault();
    this.emit({
      type: 'seek',
      sequence: view.state.sequence,
      percentage: Math.max(0, Math.min(1, percentage)),
    });
  }

  private setButton(button: HTMLButtonElement, label: string, icon: string): void {
    button.title = label;
    button.setAttribute('aria-label', label);
    button.innerHTML = icon;
  }

  private emit(action: PlaybackControlsAction): void {
    this.actionCallback?.(action);
  }
}

function pointerPercentage(element: HTMLElement, event: MouseEvent | PointerEvent): number {
  const bounds = element.getBoundingClientRect();
  return Math.max(0, Math.min(1, (event.clientX - bounds.left) / bounds.width));
}

function formatTime(value: number): string {
  const seconds = Math.max(0, Math.floor(value));
  const hours = Math.floor(seconds / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  const remainder = seconds % 60;
  if (hours > 0) {
    return `${hours}:${String(minutes).padStart(2, '0')}:${String(remainder).padStart(2, '0')}`;
  }
  return `${minutes}:${String(remainder).padStart(2, '0')}`;
}
