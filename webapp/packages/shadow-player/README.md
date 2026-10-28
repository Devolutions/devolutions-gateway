# @devolutions/shadow-player

Play a live Gateway recording with the `shadow-player` custom element.
The component owns its WebSocket, MediaSource buffers, playback readiness, and live-edge catch-up.
Consumers do not need access to its video elements or media event handlers.

```typescript
import '@devolutions/shadow-player';
import type { ShadowPlayer } from '@devolutions/shadow-player';

const player = document.createElement('shadow-player') as ShadowPlayer;
player.setControls(false);
player.onReady(() => console.log('First clip is playable'));
player.onError(error => console.error('Live playback failed', error));
player.onEnd(() => console.log('Gateway finished sending the recording'));
container.appendChild(player);
player.srcChange(shadowUrl);
player.play();

// Stop playback and release the connection and buffered media.
player.disconnect();
player.remove();
```

## Public lifecycle

`setControls(enabled: boolean): void` enables or disables the built-in playback controls, replay button, and click-to-toggle behavior.
Controls remain enabled by default for compatibility; registering `onEnd()` does not change the controls setting.
Removing the `controls` attribute also disables controls.

`play(): void` requests playback and starts when a clip becomes playable.
`pause(): void` cancels that playback intent.
Autoplay and media playback failures are delivered through `onError()`, not unhandled promise rejections.
Media errors from retained clips still reach `onError()` after the server finishes sending or the connection closes.
A rejected autoplay request leaves the player paused; call `play()` again after a user gesture to retry.

`onReady(callback)` runs when the first playable clip is selected, not when the WebSocket opens.
`onEnd(callback)` reports that the Gateway finished sending the stream; buffered playback may still be in progress.
`onError(callback)` receives a `ShadowPlayerError`, including session-not-found, protocol, connection, and player failures.
Each registration replaces that callback.
`onEnd(callback)` and `onError(callback)` listen for future events, preserving existing registration behavior.
Use `onEnd(callback, { replay: true })` or `onError(callback, { replay: true })` to also receive a retained outcome immediately during registration.
Late `onReady(callback)` registration receives retained readiness immediately.
Retained outcomes are cleared when the source changes or the player disconnects.
Callback return values are ignored, preserving support for callbacks that return an assignment or dispatch result.
Async ready/end callback failures are reported through `onError()`.

`srcChange(url: string): void` replaces the current connection and releases its buffers.
`disconnect(): void` cancels the connection, pending buffer work, and playback; removing the element also disconnects it.
Late events from cancelled sessions are ignored.

## Buffered playback

Playback starts inside the available buffered ranges, including streams whose first media timestamp is nonzero.
Timeline positions use buffered media, without overriding the native media duration.
While following live playback, falling more than five seconds behind the receiving clip jumps to 0.25 seconds behind its newest buffered frame.
Pausing or seeking into history stops live following until playback returns near the live edge.
Older segments are released according to the existing retention limit.
