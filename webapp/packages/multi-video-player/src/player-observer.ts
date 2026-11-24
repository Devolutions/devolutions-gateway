import videojs from 'video.js';
import type Player from 'video.js/dist/types/player';

interface PlayerSource {
  src: string;
  type?: string;
  multiVideoPlayerLoadId?: symbol;
}

interface PlayerObserver {
  playbackCommand: (playing: boolean) => void;
  isInternalPause: (nativeEnded: boolean) => boolean;
  shouldHoldPlay: () => boolean;
  interceptPlay?: () => Promise<void> | undefined;
  paused?: () => boolean | undefined;
  ended?: () => boolean | undefined;
  sourceChange: (source: PlayerSource) => void;
}

interface PlayerState {
  observer?: PlayerObserver;
  playing: boolean;
  hasPlaybackCommand: boolean;
  playback?: Promise<unknown>;
}

const states = new WeakMap<Player, PlayerState>();

export function observePlayer(player: Player, observer: PlayerObserver) {
  const state: PlayerState = states.get(player) ?? { playing: !player.paused(), hasPlaybackCommand: false };
  state.observer = observer;
  states.set(player, state);
  const originalPlay = player.play;
  const originalPause = player.pause;
  let commandId = 0;
  let endedEvent: Event | undefined;
  let endedPausePending = false;
  const captureEnded = (event: Event) => {
    endedEvent = event;
    endedPausePending = !player.paused();
  };
  const root = player.el();
  root.addEventListener('ended', captureEnded, true);
  const pendingPlay = new Set<(error: Error) => void>();
  function cancelPlay() {
    for (const reject of pendingPlay) {
      reject(new DOMException('playback interrupted', 'AbortError'));
    }
    pendingPlay.clear();
  }
  function play(this: Player) {
    if (observer.shouldHoldPlay()) {
      return Promise.resolve();
    }
    commandId++;
    state.playing = true;
    state.hasPlaybackCommand = true;
    state.playback = undefined;
    observer.playbackCommand(true);
    const intercepted = observer.interceptPlay?.();
    if (intercepted) {
      return intercepted;
    }
    const playing = originalPlay.call(this);
    if (!playing) {
      return playing;
    }
    let cancel!: (error: Error) => void;
    const cancelled = new Promise<never>((_resolve, reject) => {
      cancel = reject;
    });
    pendingPlay.add(cancel);
    const playback = Promise.race([playing, cancelled]).finally(() => pendingPlay.delete(cancel));
    state.playback = playback;
    return playback;
  }
  function pause(this: Player) {
    // Video.js pauses inside its native ended handler; that is not a recording Pause command.
    const nativeEnded = !!endedEvent?.eventPhase && endedPausePending;
    if (nativeEnded) {
      endedPausePending = false;
    }
    if (observer.isInternalPause(nativeEnded)) {
      originalPause.call(this);
      return;
    }
    const command = ++commandId;
    state.playing = false;
    state.hasPlaybackCommand = true;
    state.playback = undefined;
    cancelPlay();
    observer.playbackCommand(false);
    if (command === commandId) {
      originalPause.call(this);
    }
  }
  const guardNativePlay = () => {
    if (state.observer === observer && state.hasPlaybackCommand && !state.playing && !player.paused()) {
      player.pause();
    }
  };
  // Middleware sees deferred execution; these scoped wrappers record request order.
  player.play = play;
  player.pause = pause;
  player.on('play', guardNativePlay);
  return () => {
    root.removeEventListener('ended', captureEnded, true);
    player.off('play', guardNativePlay);
    cancelPlay();
    if (state.observer === observer) {
      state.observer = undefined;
      state.playback = undefined;
    }
    if (player.play === play) {
      player.play = originalPlay;
    }
    if (player.pause === pause) {
      player.pause = originalPause;
    }
  };
}

export function playbackIntent(player: Player) {
  const state = states.get(player);
  return state?.hasPlaybackCommand ? state.playing : !player.paused();
}

export function finishPlayback(player: Player) {
  const state = states.get(player);
  if (!state) {
    throw new Error('player is not observed');
  }
  state.playing = false;
  state.hasPlaybackCommand = true;
  state.playback = undefined;
}

export async function settlePlayback(player: Player, initial?: Promise<unknown>) {
  const state = states.get(player);
  let playback = initial ?? state?.playback;
  for (;;) {
    try {
      await playback;
    } catch (error) {
      if (state?.playback === playback) {
        throw error;
      }
    }
    if (!state || state.playback === playback) {
      return;
    }
    playback = state.playback;
  }
}

videojs.use('*', (player: Player) => ({
  setSource(source: PlayerSource, next: (error: Error | null, source: PlayerSource) => void) {
    states.get(player)?.observer?.sourceChange(source);
    next(null, source);
  },
  callPlay() {
    const state = states.get(player);
    return state?.observer && !state.playing ? videojs.middleware.TERMINATOR : null;
  },
  paused(paused: boolean) {
    return states.get(player)?.observer?.paused?.() ?? paused;
  },
  ended(ended: boolean) {
    return states.get(player)?.observer?.ended?.() ?? ended;
  },
}));
