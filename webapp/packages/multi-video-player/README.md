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

Times use each clip's `SourceMetadata.duration`, not its reported media duration, and clips form a back-to-back timeline.
Playlist metadata is fixed for each `play()` initialization; call `play()` again to apply changes.
Durations must be finite and nonnegative.
Source URLs must be nonempty strings, not whitespace.
Before a playlist is initialized, `currentTime` and `duration` are `0`, `currentClipIndex` is `-1`, and `seek()` and `resume()` resolve without loading a source.
After disposal, the getters return those same empty values and `seek()` and `resume()` reject with `InvalidStateError`.

`seek(seconds): Promise<void>` clamps finite times to `[0, duration]` and rejects non-finite input with `RangeError`.
An exact clip boundary selects the next nonempty clip; the playlist endpoint selects the end of the last clip.
The promise resolves after the offset is applied and playback matches the latest Play/Pause command.
The clock reports the requested target during loading; await the promise before treating the seek as complete.
Calling `pause()` or using the built-in Play/Pause controls during loading updates the pending playback state.
Loading or playback errors reject the promise, including seeking within a clip that has already failed to load.
An unsupported initial source rejects `play()`; seeking to an unsupported clip rejects `seek()` without replacing the current source.
A newer seek, a replacement playlist, or disposal rejects an unfinished seek with `AbortError`.

`resume(): Promise<void>` starts the current playlist at its current position without reinitializing it.
For **Play from event**, await `seek(eventPosition)` and then await `resume()`.
Calling `resume()` during a seek updates its pending playback intent.
The promise resolves when the playback request succeeds; it does not wait for a pending seek's offset to be applied.
A later Pause command, playlist replacement, or disposal rejects an unfinished resume with `AbortError`.
Media loading and autoplay errors reject the promise.

`timeupdate` is a `CustomEvent<{ currentTime: number; clipIndex: number }>` dispatched when the clock updates, including initialization and seeking.
`clipchange` is a `CustomEvent<{ clipIndex: number }>` dispatched when a playlist is initialized or the active clip changes.
Both events are dispatched on the custom element and do not bubble.
Use non-capturing listeners to receive typed custom events; capturing `timeupdate` listeners can also receive native video events without `detail`.

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