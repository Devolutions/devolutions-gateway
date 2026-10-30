import videojs from 'video.js';
import { ProgressManagerHandle } from '../src/progress-manager';
import { MultiVideoPlayer, type SourceMetadata } from '../src/video-player/player';
import { MultiVideoProgressControl } from '../src/video-player/progress-control';

const playlist: SourceMetadata[] = [
  { src: 'first.webm', type: 'video/webm', duration: 10.5 },
  { src: 'second.webm', type: 'video/webm', duration: 20 },
  { src: 'third.webm', type: 'video/webm', duration: 30.25 },
];

describe('video.js progress controls', () => {
  let css: PropertyDescriptor | undefined;
  let element: MultiVideoPlayer;
  let player: ReturnType<typeof videojs>;
  let control: MultiVideoProgressControl;
  let time: number;

  beforeEach(() => {
    css = Object.getOwnPropertyDescriptor(window, 'CSS');
    Object.defineProperty(window, 'CSS', { configurable: true, value: { supports: () => false } });
    jest.spyOn(HTMLMediaElement.prototype, 'load').mockImplementation(() => {});
    jest.spyOn(HTMLMediaElement.prototype, 'pause').mockImplementation(() => {});
    jest.spyOn(HTMLMediaElement.prototype, 'play').mockResolvedValue();
    jest.spyOn(HTMLMediaElement.prototype, 'canPlayType').mockReturnValue('probably');
    element = new MultiVideoPlayer();
    document.body.appendChild(element);
    const created = videojs.getPlayer('my-video');
    if (!created) {
      throw new Error('video.js player was not created');
    }
    player = created;
    const progress = player.getChild('controlBar')?.getChild('MultiVideoProgressControl');
    if (!(progress instanceof MultiVideoProgressControl)) {
      throw new Error('progress control was not created');
    }
    control = progress;
    time = 0;
    jest.spyOn(player, 'readyState').mockReturnValue(1);
    jest.spyOn(player, 'currentTime').mockImplementation((value) => {
      if (value !== undefined) {
        time = Number(value);
      }
      return time;
    });
    jest.spyOn(player, 'paused').mockReturnValue(true);
  });

  afterEach(async () => {
    try {
      await element.dispose();
    } finally {
      element.remove();
      jest.restoreAllMocks();
      if (css) {
        Object.defineProperty(window, 'CSS', css);
      } else {
        Reflect.deleteProperty(window, 'CSS');
      }
    }
  });

  async function start(sources = playlist) {
    const installed = new Promise<void>((resolve) => player.one('sourceset', () => resolve()));
    await element.play(sources);
    await installed;
    player.trigger('loadedmetadata');
  }

  function clickClip(index: number, percentage: number): Promise<void> {
    const bar = element.querySelectorAll<HTMLElement>('.vjs-progress-holder')[index];
    if (!bar) {
      throw new Error('clip seek bar was not created');
    }
    jest.spyOn(bar, 'clientWidth', 'get').mockReturnValue(200);
    jest.spyOn(bar, 'getBoundingClientRect').mockReturnValue({
      x: 100,
      y: 0,
      left: 100,
      right: 300,
      top: 0,
      bottom: 10,
      width: 200,
      height: 10,
      toJSON: () => ({}),
    });
    const seek = jest.spyOn(ProgressManagerHandle.prototype, 'userSeek');
    bar.dispatchEvent(new MouseEvent('mousedown', { bubbles: true, cancelable: true, clientX: 100 + percentage * 2 }));
    const request = seek.mock.results[seek.mock.results.length - 1];
    if (!request || request.type !== 'return') {
      throw new Error('mouse-down did not return a seek request');
    }
    return request.value;
  }

  it('updates real video.js progress bars and replaces them when the playlist changes', async () => {
    await start();
    const targetInstalled = new Promise<void>((resolve) => player.one('sourceset', () => resolve()));
    const seeking = element.seek(40);
    expect(time).toBe(0);
    await targetInstalled;
    player.trigger('loadedmetadata');
    await seeking;
    await new Promise<void>((resolve) => requestAnimationFrame(() => resolve()));
    const bars = element.querySelectorAll<HTMLElement>('.vjs-devolutions-play-progress');
    expect([...bars].map((bar) => bar.style.width)).toEqual(['100%', '100%', '31%']);

    const oldChildren = [...control.children()];
    await element.play([{ src: 'replacement.webm', type: 'video/webm', duration: 5 }]);
    expect(control.children()).toHaveLength(1);
    expect(element.querySelectorAll('.vjs-devolutions-play-progress')).toHaveLength(1);
    expect(oldChildren.every((child) => child.isDisposed())).toBe(true);
  });

  it('seeks to the clicked clip offset after metadata is ready', async () => {
    await start();
    const log = jest.spyOn(console, 'error').mockImplementation(() => {});
    const installed = new Promise<void>((resolve) => player.one('sourceset', () => resolve()));
    const seeking = clickClip(1, 25);
    expect(time).toBe(0);
    expect(element.currentClipIndex).toBe(1);
    await installed;
    player.trigger('loadedmetadata');
    await seeking;
    expect(time).toBe(5);
    expect(element.currentTime).toBe(15.5);
    expect(log).not.toHaveBeenCalled();
  });

  it('does not log an error when a mouse seek is superseded', async () => {
    await start();
    const log = jest.spyOn(console, 'error').mockImplementation(() => {});
    const installed = new Promise<void>((resolve) => player.one('sourceset', () => resolve()));
    const clicked = clickClip(1, 25);
    const cancelled = expect(clicked).rejects.toMatchObject({ name: 'AbortError' });
    const latest = element.seek(20.5);
    await cancelled;
    await installed;
    player.trigger('loadedmetadata');
    await latest;
    expect(time).toBe(10);
    expect(element.currentTime).toBe(20.5);
    expect(log).not.toHaveBeenCalled();
  });

  it('logs a genuine mouse seek failure without replacing the current source', async () => {
    jest
      .mocked(HTMLMediaElement.prototype.canPlayType)
      .mockImplementation((type) => (type === 'application/unsupported' ? '' : 'probably'));
    await start([playlist[0], { ...playlist[1], type: 'application/unsupported' }]);
    const source = player.currentSrc();
    const log = jest.spyOn(console, 'error').mockImplementation(() => {});
    await expect(clickClip(1, 25)).rejects.toThrow('no compatible source was found for this media');
    expect(log).toHaveBeenCalledWith(
      'Seek failed:',
      expect.objectContaining({ message: 'no compatible source was found for this media' }),
    );
    expect(player.currentSrc()).toBe(source);
    expect(element.currentClipIndex).toBe(0);
    await expect(element.seek(2)).resolves.toBeUndefined();
  });
});
