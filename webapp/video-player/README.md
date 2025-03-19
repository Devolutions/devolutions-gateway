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

Simply include the JavaScript and CSS files in your HTML document:

```html
<link rel="stylesheet" href="./dist/multi-video-player.css" />
<script src="./dist/multi-video-player.js" type="module"></script>
```

Then use the custom element in your HTML:

```html
<multi-video-player width="800" height="700" muted controls></multi-video-player>
```

### Basic Implementation

Complete example of using the web component:

```html
<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>Multi Video Player Example</title>
    <link rel="stylesheet" href="./dist/multi-video-player.css" />
  </head>
  <body>
    <multi-video-player width="800" height="700" muted controls></multi-video-player>
    
    <script src="./dist/multi-video-player.js" type="module"></script>
    <script type="module">
      import { MultiVideoPlayer } from './dist/multi-video-player.js';
      
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
// Play a list of videos
player.play(playList: SourceMetadata[]);

// SourceMetadata interface
interface SourceMetadata {
  src: string;      // URL to the video file
  duration: number; // Duration in seconds
  type: string;     // MIME type of the video (e.g., 'video/mp4')
}
```

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