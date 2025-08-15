import videojs from 'video.js';
import Player from 'video.js/dist/types/player';
import './custom-play-progress-bar';
import './custom-time-tooltip';
import { Options, Percentage, Status } from '../util';
import CustomPlayProgressBar from './custom-play-progress-bar';
import CustomTimeTooltip from './custom-time-tooltip';

const Slider = videojs.getComponent('Slider');

export class SingleVideoSeekBar extends Slider {
  private progress;

  constructor(player: Player, options?: Options) {
    super(player, options);
    if (!options?.progressHandle) {
      throw new Error('progressHandle is required');
    }

    this.progress = options.progressHandle;

    this.setAttribute('style', `flex-basis: ${this.progress.getPercentageLength()}%;`);

    this.progress.onStatusUpdate((status) => {
      this.update(status);
    });

    this.el().addEventListener('mousedown', (e) => this.handleMouseDown(e as MouseEvent));
    this.el().addEventListener('mousemove', (e) => this.handleMouseMove(e as MouseEvent));
    this.el().addEventListener('mouseenter', () => this.handleMouseEntre());
    this.el().addEventListener('mouseleave', () => this.handleMouseLeave());
  }

  createEl(): Element {
    const element = super.createEl('div', {
      className: 'vjs-progress-holder',
    });

    return element;
  }

  handleMouseDown(event: MouseEvent) {
    event.preventDefault();
    if (!event.target || !(event.target === this.el())) {
      return;
    }

    this.progress.userSeek(this.getPositionPercentage(event));
  }

  handleMouseEntre() {
    const tooltip = this.getChild('customTimeTooltip') as CustomTimeTooltip;
    tooltip.show();
  }

  handleMouseLeave() {
    const tooltip = this.getChild('customTimeTooltip') as CustomTimeTooltip;
    tooltip.hide();
  }

  handleMouseMove(event: MouseEvent) {
    const mousePercentage = this.getPositionPercentage(event);
    const tooltip = this.getChild('customTimeTooltip') as CustomTimeTooltip;
    tooltip.update(this.progress.percentageToTime(mousePercentage), mousePercentage);
  }

  update(status: Status) {
    const playProgress = this.getChild('customPlayProgressBar') as CustomPlayProgressBar | undefined;

    if (!playProgress) {
      return;
    }

    const update = (percentage: Percentage) => {
      playProgress.update(percentage);
    };

    if (status.status === 'playing') {
      update(status.percentage);
    }

    if (status.status === 'ended') {
      update(Percentage.full());
    }

    if (status.status === 'NotStarted') {
      update(Percentage.zero());
    }
  }

  private getPositionPercentage(event: MouseEvent) {
    const rect = (event.target as HTMLElement)?.getBoundingClientRect();
    const x = event.clientX - rect.left;
    const elWidth = this.el().clientWidth;
    return Percentage.devidedBy(x, elWidth);
  }
}

SingleVideoSeekBar.prototype.options_ = {
  children: ['customPlayProgressBar', 'customTimeTooltip'],
  barName: 'singleVideoSeekBar',
};

videojs.registerComponent('SingleVideoSeekBar', SingleVideoSeekBar);
