import { handleWebm } from './webm.js';
export const getShadowPlayer = (fileType) => {
  const player = {
    play: () => {},
  };

  if (fileType === 'webm') {
    player.play = handleWebm;
  }

  return player;
};
