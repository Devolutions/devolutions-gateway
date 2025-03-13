import Player from 'video.js/dist/types/player';
import { Percentage, Status, VideoTime } from './util';
import { SourceMetadata } from './video-player/player';
import { SingleVideoSeekBar } from './video-player/single-video-seek-bar';

export class ProgressManager {
  handles: ProgressManagerHandle[] = [];
  playList: SourceMetadata[] = [];
  currentlyPlayingSrc: string | undefined;
  player: Player;

  constructor(player: Player, playList: SourceMetadata[]) {
    this.playList = playList;
    this.player = player;

    this.player.on(['play'], () => {
      this.currentlyPlayingSrc = this.player.currentSrc();
      this.updateCurrentHandle({
        status: 'playing',
        percentage: Percentage.devidedBy(this.player.currentTime() || 0, this.player.duration() || 1),
      });
    });

    this.player.on(['ended'], () => {
      const handle = this.currentPlayingHandle();
      if (handle) {
        handle.status = { status: 'ended' };
        if (this.playList.length > handle.index + 1) {
          this.playList[handle.index + 1].src;
          this.player.src(this.playList[handle.index + 1].src);
          this.player.play();
        } else {
          this.player.src(this.playList[0].src);
        }
      }
    });

    this.player.on(['durationchange', 'timeupdate'], () => {
      this.updateCurrentHandle({
        status: 'playing',
        percentage: Percentage.devidedBy(this.player.currentTime() || 0, this.player.duration() || 1),
      });
    });

    this.handles = playList.map((source, index) => {
      return new ProgressManagerHandle(this, source, index);
    });
  }

  forEachHandle(acceptCallback: (worker: ProgressManagerHandle) => void) {
    for (const worker of this.handles) {
      acceptCallback(worker);
    }
  }

  userSeek(seekHandle: ProgressManagerHandle, percentage: Percentage) {
    if (seekHandle !== this.currentPlayingHandle()) {
      // We need to jump to another video
      for (const handle of this.handles) {
        if (handle.index < seekHandle.index) {
          handle.status = { status: 'ended' };
        } else if (handle.index === seekHandle.index) {
          handle.status = { status: 'playing', percentage };
        } else {
          handle.status = { status: 'NotStarted' };
        }
      }

      this.player.src(seekHandle.souce.src);
      this.player.play();
      this.player.currentTime(seekHandle.souce.duration * percentage.toDecimal());
    } else {
      // update currend duration
      this.player.currentTime((this.player.duration() || 1) * percentage.toDecimal());
    }
  }

  getVideoDurationPercentage(worker: ProgressManagerHandle) {
    const total = this.playList.reduce((acc, source) => acc + source.duration, 0);

    return Math.round((worker.souce.duration / total) * 100);
  }

  private currentPlayingHandle() {
    return this.handles.find((handle) => handle.souce.src === this.player.currentSrc());
  }

  private updateCurrentHandle(status: Status) {
    const handle = this.currentPlayingHandle();
    if (handle) {
      handle.status = status;
    }
  }
}

export class ProgressManagerHandle {
  souce: SourceMetadata;
  index: number;
  manager: ProgressManager;
  component: SingleVideoSeekBar | undefined;
  private _status: Status = { status: 'NotStarted' };
  private statusUpdateCallback: ((status: Status) => void) | undefined;

  constructor(manager: ProgressManager, souce: SourceMetadata, index: number) {
    this.souce = souce;
    this.index = index;
    this.manager = manager;
  }

  set status(value: Status) {
    this.statusUpdateCallback?.(value);
    this._status = value;
  }

  get status() {
    return this._status;
  }

  register(component: SingleVideoSeekBar) {
    this.component = component;
  }

  onStatusUpdate(callback: (status: Status) => void) {
    this.statusUpdateCallback = callback;
  }

  // For the width of each single video seek bar
  getPercentageLength() {
    return this.manager.getVideoDurationPercentage(this);
  }

  userSeek(percentage: Percentage) {
    this.manager.userSeek(this, percentage);
  }

  percentageToTime(percentage: Percentage) {
    let timeAccumulatedBefore = 0;
    this.manager.forEachHandle((handle) => {
      if (handle.index < this.index) {
        timeAccumulatedBefore += handle.souce.duration;
      }
    });
    const currentVIdeoTime = timeAccumulatedBefore + this.souce.duration * percentage.toDecimal();
    return new VideoTime(currentVIdeoTime);
  }
}
