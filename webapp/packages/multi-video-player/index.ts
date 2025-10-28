import './src/vite-env.d.ts';
import './src/index.ts';
import { MultiVideoPlayer } from './src/index.ts';

const src1 = import.meta.env.VITE_VIDEO_SRC_1;
const src2 = import.meta.env.VITE_VIDEO_SRC_2;
const src1_length = import.meta.env.VITE_VIDEO_SRC_1_LENGTH;
const src2_length = import.meta.env.VITE_VIDEO_SRC_2_LENGTH;
const src1_type = import.meta.env.VITE_VIDEO_SRC_1_TYPE;
const src2_type = import.meta.env.VITE_VIDEO_SRC_2_TYPE;

const playList = [
  {
    src: src1,
    type: src1_type,
    duration: Number.parseInt(src1_length),
  },
  {
    src: src2,
    type: src2_type,
    duration: Number.parseInt(src2_length),
  },
];

// Wait for the component to be defined
customElements.whenDefined('multi-video-player').then(() => {
  const player = document.querySelector('multi-video-player') as MultiVideoPlayer;

  player.play(playList);
});
