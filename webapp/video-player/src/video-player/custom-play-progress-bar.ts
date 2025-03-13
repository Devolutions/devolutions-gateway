import videojs from 'video.js';
import Player from 'video.js/dist/types/player';
import { Options, Percentage } from '../util';

const Component = videojs.getComponent('Component');

class CustomPlayProgressBar extends Component {
  constructor(player: Player, options?: Options) {
    super(player, options);
  }

  createEl() {
    return super.createEl('div', {
      className: 'vjs-devolutions-play-progress',
    });
  }

  public update(percentage: Percentage) {
    this.requestNamedAnimationFrame('PlayProgressBar#update', () => {
      this.el_.style.width = percentage.toStyle();
    });
  }

  dispose() {
    super.dispose();
  }
}

videojs.registerComponent('CustomPlayProgressBar', CustomPlayProgressBar);
export default CustomPlayProgressBar;
