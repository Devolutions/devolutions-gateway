import { GatewayAccessApi } from '../gateway';
import { handleWebm } from './webm';

export const getShadowPlayer = (fileType) => {
  const player = {
    play: (_: GatewayAccessApi) => {},
  };

  if (fileType === 'webm') {
    player.play = handleWebm;
  }

  return player;
};
