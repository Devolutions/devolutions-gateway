import type {Subscription} from 'rxjs';
import {WebMRecorder} from '@devolutions/web-recorder';
import {MilkyWayScene} from './milky-way';
import {buildPushUrl, requestPushToken} from './token-client';

const canvas = el<HTMLCanvasElement>('stage');
const gatewayInput = el<HTMLInputElement>('gateway');
const animateButton = el<HTMLButtonElement>('animate');
const startButton = el<HTMLButtonElement>('start');
const stopButton = el<HTMLButtonElement>('stop');
const statusLine = el<HTMLDivElement>('status');
const recordingIdLine = el<HTMLDivElement>('recording-id');

const scene = new MilkyWayScene(canvas);
let recorder: WebMRecorder | null = null;
let subscription: Subscription | null = null;
let animating = false;

// Render one static frame on load and leave the animation stopped, so a recording can be made
// against a genuinely static canvas — the scenario that triggered the empty-WebM bug.
scene.renderStaticFrame();

animateButton.addEventListener('click', () => {
  animating = !animating;
  if (animating) {
    scene.start();
    animateButton.textContent = 'Stop animation';
  } else {
    scene.stop();
    animateButton.textContent = 'Start animation';
  }
});

startButton.addEventListener('click', () => void startRecording());
stopButton.addEventListener('click', () => stopRecording());

async function startRecording(): Promise<void> {
  startButton.disabled = true;
  const sessionId = crypto.randomUUID();
  const gatewayHost = gatewayInput.value.trim() || 'localhost:7171';

  try {
    setStatus(`Requesting push token for ${sessionId}…`);
    const token = await requestPushToken(sessionId);
    const pushUrl = buildPushUrl(gatewayHost, sessionId, token);

    recorder = new WebMRecorder({
      onTelemetry: event => console.log('[web-recorder telemetry]', event),
    });

    subscription = recorder.start(canvas, pushUrl).subscribe({
      next: () => setStatus('Recording — frames are streaming to the Gateway.', 'ok'),
      error: (err: unknown) => {
        setStatus(`Recorder error: ${String(err)}`, 'err');
        teardown();
      },
      complete: () => setStatus('Recording channel closed.'),
    });

    stopButton.disabled = false;
    recordingIdLine.textContent = `Recording id: ${sessionId}`;
    setStatus('Recorder started — waiting for the first frame…');
  } catch (err: unknown) {
    setStatus(`Failed to start: ${String(err)}`, 'err');
    teardown();
    startButton.disabled = false;
  }
}

function stopRecording(): void {
  recorder?.stop();
  const id = recordingIdLine.textContent?.replace('Recording id: ', '') ?? '';
  teardown();
  if (id) {
    setStatus(`Saved. Play it in recording-player-tester with session id ${id}.`, 'ok');
  }
}

function teardown(): void {
  subscription?.unsubscribe();
  subscription = null;
  recorder = null;
  stopButton.disabled = true;
  startButton.disabled = false;
}

function setStatus(message: string, kind: 'ok' | 'err' | 'info' = 'info'): void {
  statusLine.textContent = message;
  statusLine.dataset.kind = kind;
}

function el<T extends HTMLElement>(id: string): T {
  const node = document.getElementById(id);
  if (!node) {
    throw new Error(`missing element #${id}`);
  }
  return node as T;
}
