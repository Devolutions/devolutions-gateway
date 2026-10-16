import videojs from 'video.js';
import type Player from 'video.js/dist/types/player';

interface PlayerSource {
  src: string;
  type?: string;
  multiVideoPlayerLoadId?: symbol;
}

interface PlayerObserver {
  playbackCommand: (playing: boolean) => void;
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
  const pendingPlay = new Set<(error: Error) => void>();
  function cancelPlay() {
    for (const reject of pendingPlay) {
      reject(new DOMException('playback interrupted', 'AbortError'));
    }
    pendingPlay.clear();
  }
  function play(this: Player) {
    state.playing = true;
    state.hasPlaybackCommand = true;
    state.playback = undefined;
    observer.playbackCommand(true);
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
    state.playing = false;
    state.hasPlaybackCommand = true;
    state.playback = undefined;
    observer.playbackCommand(false);
    cancelPlay();
    originalPause.call(this);
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
}));
