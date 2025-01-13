import { GatewayAccessApi } from '../gateway';
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
