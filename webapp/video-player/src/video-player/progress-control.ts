import videojs from 'video.js';
import Player from 'video.js/dist/types/player';
import './single-video-seek-bar';
import { ReadyCallback } from 'video.js/dist/types/component';
import { ProgressManager } from '../progress-manager';
import { Options } from '../util';

const Component = videojs.getComponent('Component');
export class MultiVideoProgressControl extends Component {
  constructor(player: Player, options?: Options, ready?: ReadyCallback) {
    super(player, { ...options, children: [] }, ready);
  }

  createEl() {
    return super.createEl('div', {
      className: 'vjs-devolutions-progress-control',
    });
  }

  public setProgressManager(progressManager: ProgressManager) {
    progressManager.forEachHandle((handle) => {
      this.addChild('SingleVideoSeekBar', {
        progressHandle: handle,
      });
    });
  }
}

videojs.registerComponent('MultiVideoProgressControl', MultiVideoProgressControl);
