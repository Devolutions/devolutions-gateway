import { GatewayAccessApi } from '../gateway';
import { removeTerminal } from '../terminal';
import { handleCast } from './cast';
import { handleWebm } from './webm';
export const getShadowPlayer = (fileType) => {
  const player = {
    play: (_: GatewayAccessApi) => {},
  };

  if (fileType === 'webm') {
    player.play = handleWebm;
  }

  if (fileType === 'cast' || fileType === 'trp') {
    player.play = handleCast;
  }

  return player;
};

export const cleanUpStreamers = () => {
  // Remove all shadow-player elements.
  const shadowPlayers = document.querySelectorAll('shadow-player');
  for (const shadowPlayer of shadowPlayers) {
    shadowPlayer.remove();
  }
  removeTerminal();
};
