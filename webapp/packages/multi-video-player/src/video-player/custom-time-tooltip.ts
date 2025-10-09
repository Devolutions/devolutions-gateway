import videojs from 'video.js';
import Player from 'video.js/dist/types/player';
import { Options, Percentage, VideoTime } from '../util';

const Component = videojs.getComponent('Component');

export class CustomTimeTooltip extends Component {
  constructor(player: Player, options: Options) {
    super(player, options);
  }

  update(time: VideoTime, postion: Percentage) {
    this.requestNamedAnimationFrame('CustomTimeTooltip#update', () => {
      this.updateStyle({
        left: postion.toStyle(),
        transform: 'translateX(-50%)',
      });
      this.el().innerHTML = time.formatted();
    });
  }

  show() {
    this.updateStyle({
      visibility: 'visible',
    });
  }

  hide() {
    this.updateStyle({
      visibility: 'hidden',
    });
  }

  createEl() {
    return super.createEl(
      'div',
      {
        className: 'vjs-time-tooltip',
      },
      {
        'aria-hidden': 'true',
      },
    );
  }

  private updateStyle(style: Partial<CSSStyleDeclaration>) {
    const element = this.el() as HTMLElement;
    Object.assign(element.style, style);
  }
}

videojs.registerComponent('CustomTimeTooltip', CustomTimeTooltip);
export default CustomTimeTooltip;
