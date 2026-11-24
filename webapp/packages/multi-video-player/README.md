# @devolutions/multi-video-player

A custom web component video player built on top of video.js that specializes in playing multiple videos in sequence with a unified progress bar control.

## Features

- Play multiple video files sequentially through a unified interface
- Custom progress bar showing combined video duration
- Individual seek bars for each video in the playlist
- Video time tooltips showing position within the entire playlist
- Custom controls including play/pause, volume, progress, and fullscreen
- TypeScript implementation with full type safety

## Usage

### Including the Web Component

In a project using a bundler such as Vite, install the package and import the component and its stylesheet:

```javascript
import '@devolutions/multi-video-player';
import '@devolutions/multi-video-player/index.css';
```

Then use the custom element in your HTML:

```html
<multi-video-player width="800" height="700" muted controls></multi-video-player>
```

### Basic Implementation

For example, use this `index.html` in a Vite project with the package installed:

```html
<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>Multi Video Player Example</title>
  </head>
  <body>
    <multi-video-player width="800" height="700" muted controls></multi-video-player>
    
    <script type="module">
      import '@devolutions/multi-video-player';
      import '@devolutions/multi-video-player/index.css';
      
      // Define your playlist
      const playList = [
        {
          src: 'example-videos/video-1.mp4',
          type: 'video/mp4',
          duration: 120 // duration in seconds
        },
        {
          src: 'example-videos/video-2.webm',
          type: 'video/webm',
          duration: 180 // duration in seconds
        }
      ];

      // Wait for the component to be defined
      customElements.whenDefined('multi-video-player').then(() => {
        const player = document.querySelector('multi-video-player');
        player.play(playList);
      });
    </script>
  </body>
</html>
```

### API Reference

#### `<multi-video-player>` Element

The custom element supports the following attributes:

- `width`: Video player width
- `height`: Video player height
- `controls`: Shows video controls when present
- `autoplay`: Attempts to autoplay when present
- `muted`: Mutes the audio when present

#### JavaScript API

```typescript
// Initialize a playlist; the autoplay attribute controls automatic playback.
await player.play(playList);

// Read recording-relative seconds and the zero-based active clip.
player.currentTime;
player.duration;
player.currentClipIndex;

// Seek without changing the paused/playing state.
await player.seek(45);

// Start playback at that position without replacing the playlist.
await player.resume();

player.addEventListener('timeupdate', (event) => {
  console.log(event.detail.currentTime, event.detail.clipIndex);
});
player.addEventListener('clipchange', (event) => {
  console.log(event.detail.clipIndex);
});

player.pause();
await player.dispose();

// SourceMetadata interface
interface SourceMetadata {
  src: string;      // URL to the video file
  duration: number; // Duration in seconds
  type: string;     // MIME type of the video (e.g., 'video/mp4')
}
```

The global timeline uses each clip's `SourceMetadata.duration` and places clips back to back.
If video ends early, its final frame is held while recording time continues to the declared clip boundary.
Pause freezes this clock; Play resumes it without restarting the exhausted video.
Observed local time and finite media duration come from the loaded clip.
The read-only `playing` getter reports logical playback, including held-frame intervals; do not infer recording playback from the native video's paused or ended state.
Playlist metadata is fixed for each `play()` initialization; call `play()` again to apply changes.
Durations must be finite and nonnegative.
Source URLs must be nonempty strings, not whitespace.
Before `play()` initializes a playlist, `currentTime` and `duration` are `0`, `currentClipIndex` is `-1`, `playing` is `false`, and `seek()` and `resume()` resolve without loading a source.
While the first source loads after `play()`, `currentClipIndex` remains `-1` until metadata arrives.
Later source changes keep the previous index until new metadata arrives.
After disposal, the getters return those same empty values and `seek()` and `resume()` reject with `InvalidStateError`.

`seek(seconds): Promise<void>` clamps finite times to `[0, duration]` and rejects non-finite input with `RangeError`.
An exact clip boundary selects the next nonempty clip; the playlist endpoint selects the end of the last clip.
The local target is limited to the smaller of the declared and finite media durations.
Seeking past the native endpoint retains the requested recording position while showing that endpoint's frame.
The promise resolves after the current source reports the seek complete, current media data is available, and playback matches the latest Play/Pause command.
While seeking, the clock reports the last observed position rather than the requested target.
Calling `pause()` or using the built-in Play/Pause controls during loading updates the pending playback state.
Loading or playback errors reject the promise, including seeking within a clip that has already failed to load.
An unsupported initial source rejects `play()`; seeking to an unsupported clip rejects `seek()` without replacing the current source.
A newer seek, a replacement playlist, or disposal rejects an unfinished seek with `AbortError`.

`resume(): Promise<void>` starts the current playlist at its current position without reinitializing it.
After natural completion, the last clip remains loaded on its final frame and `resume()` restarts the playlist from the beginning.
A paused seek to the end does not count as natural completion.
At a paused seek to the declared clip endpoint, `resume()` and the Play control leave the clip paused; seek elsewhere to play.
For **Play from event**, await `seek(eventPosition)` and then await `resume()`.
Calling `resume()` during a seek updates its pending playback intent.
The promise resolves when playback succeeds or remains paused at a seek endpoint; it does not wait for a pending seek's offset to be applied.
A later Pause command, playlist replacement, or disposal rejects an unfinished resume with `AbortError`.
Media loading and autoplay errors reject the promise.

`timeupdate` and `clipchange` carry the exported `PlaybackObservation` in their `CustomEvent.detail`.
Its fields are `clipIndex`, `localTime`, optional finite native `clipDuration`, global `currentTime`, and `readiness`.
Readiness is `loading`, `seeking`, `ready`, or `ended`.
`ready` means current media data is available, not that a picture has been presented.
`clipchange` is dispatched after metadata for the active source is available.
`timeupdate` reports recording positions, including the final position before a source transition.
During a held-frame interval, `currentTime` advances while `localTime` remains at the native endpoint, with `ready` readiness until the declared playlist end.
While a source loads, the last coherent observation is retained with `loading` readiness; a failed load remains non-ready.
Both events are dispatched on the custom element and do not bubble.
Use non-capturing listeners to receive typed custom events; capturing `timeupdate` listeners can also receive native video events without `detail`.

### Live recording playback

`LiveRecordingStreamer` configures live playback without exposing video elements or requiring native media overrides.
Register lifecycle callbacks in the options so they are installed before the connection starts.

```typescript
const streamer = new LiveRecordingStreamer(api);
const player = await streamer.stream(container, {
  controls: false,
  onReady: () => hidePlayableLoadingIndicator(),
  onEnd: () => transitionToSavedRecording(),
  onError: error => showPlaybackError(error),
});

// Public commands remain available when the built-in controls are disabled.
player.pause();
player.play();
streamer.disconnect();
```

`stream(container, options?: LiveRecordingStreamOptions): Promise<ShadowPlayer>` resolves after component setup, without waiting for media readiness.
Calling `stream(container)` keeps controls enabled by default.
Existing calls also work with ShadowPlayer versions without the new lifecycle APIs.
Requesting `controls: false` or `onReady` requires a ShadowPlayer that supports that feature; otherwise setup rejects with an explicit compatibility error.
`onReady` means the first clip is playable, while `onEnd` means the server finished sending the stream, not that buffered playback finished.
The optional `onError` callback also receives session-not-found errors alongside the streamer's `onSessionNotFound()` callback.
On the updated ShadowPlayer, late `onReady` registration receives retained readiness; late `onEnd` and `onError` registration receives past outcomes only with `{ replay: true }`.
An asynchronous end callback failure is delivered through `onError`.
Disconnecting or replacing a stream cancels pending setup with `AbortError` and ignores its late callbacks.
The player handles buffered starting positions, live-edge catch-up, and autoplay failures; consumers should not override native duration or register native media listeners.

## Project Structure

- `src/video-player/player.ts`: Main web component implementation
- `src/video-player/progress-control.ts`: Custom progress control for multiple videos
- `src/video-player/single-video-seek-bar.ts`: Individual video seek bar component
- `src/video-player/custom-play-progress-bar.ts`: Custom play progress bar component
- `src/video-player/custom-time-tooltip.ts`: Custom time tooltip component
- `src/progress-manager.ts`: Manages progress across multiple videos
- `src/util.ts`: Utility functions and helper classes

## Dependencies

This web component is built on:
- [video.js](https://videojs.com/): Core video player functionality
- Web Components standard (Custom Elements)

## For Developers

### Development

To start the development server:

```bash
npm run dev
```

This starts a Vite development server that will serve the project and reload on changes.

### Building

To build the project for production:

```bash
npm run build
```

For testing purposes:
you can checkout its built output path in Vite config file and use 'npx http-server' to serve the videos in ./example-videos
You can run server.js to serve those video

```bash
npm run build:test
```

This project uses Biome for code quality:

```bash
npm run check:write
```