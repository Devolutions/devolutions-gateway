// A self-contained, continuously-animating canvas scene used to exercise WebMRecorder end-to-end:
// a rotating spiral galaxy (additive particle glow + drifting starfield) with a live wall-clock and
// elapsed-recording readout painted in the top-right corner "at the moment it is running".

interface GalaxyParticle {
  radius: number;
  angle: number;
  size: number;
  hue: number;
  bright: number;
}

interface BackgroundStar {
  x: number;
  y: number;
  size: number;
  phase: number;
  speed: number;
}

export class MilkyWayScene {
  private readonly ctx: CanvasRenderingContext2D;
  private readonly particles: GalaxyParticle[] = [];
  private readonly stars: BackgroundStar[] = [];
  private raf = 0;
  private running = false;
  private rotation = 0;
  private startMs = 0;

  // Camera: world->screen is `screen = world * scale + offset` (in canvas pixels).
  private scale = 1;
  private offsetX = 0;
  private offsetY = 0;
  private panning = false;
  private lastX = 0;
  private lastY = 0;

  constructor(private readonly canvas: HTMLCanvasElement) {
    const ctx = canvas.getContext('2d');
    if (!ctx) {
      throw new Error('2D canvas context is not available');
    }
    this.ctx = ctx;
    this.build();
    this.bindCameraControls();
  }

  start(): void {
    if (this.running) {
      return;
    }
    this.running = true;
    this.startMs = performance.now();
    this.loop();
  }

  stop(): void {
    this.running = false;
    cancelAnimationFrame(this.raf);
  }

  // Render a single frame without starting the animation loop, so the canvas can be recorded while
  // genuinely static — the scenario (no canvas changes) that triggered the empty-WebM bug.
  renderStaticFrame(): void {
    if (this.startMs === 0) {
      this.startMs = performance.now();
    }
    this.draw();
  }

  // Mouse wheel zooms toward the cursor; drag pans; double-click resets the view.
  private bindCameraControls(): void {
    const canvas = this.canvas;
    canvas.style.cursor = 'grab';
    canvas.style.touchAction = 'none';

    canvas.addEventListener(
      'wheel',
      (e: WheelEvent) => {
        e.preventDefault();
        const {x, y} = this.toCanvasCoords(e);
        const factor = e.deltaY < 0 ? 1.1 : 1 / 1.1;
        const newScale = Math.min(8, Math.max(0.25, this.scale * factor));
        const k = newScale / this.scale;
        // Keep the world point under the cursor pinned while zooming.
        this.offsetX = x - (x - this.offsetX) * k;
        this.offsetY = y - (y - this.offsetY) * k;
        this.scale = newScale;
      },
      {passive: false},
    );

    canvas.addEventListener('pointerdown', (e: PointerEvent) => {
      this.panning = true;
      const p = this.toCanvasCoords(e);
      this.lastX = p.x;
      this.lastY = p.y;
      canvas.style.cursor = 'grabbing';
      canvas.setPointerCapture(e.pointerId);
    });

    canvas.addEventListener('pointermove', (e: PointerEvent) => {
      if (!this.panning) {
        return;
      }
      const p = this.toCanvasCoords(e);
      this.offsetX += p.x - this.lastX;
      this.offsetY += p.y - this.lastY;
      this.lastX = p.x;
      this.lastY = p.y;
    });

    const endPan = (e: PointerEvent) => {
      this.panning = false;
      canvas.style.cursor = 'grab';
      try {
        canvas.releasePointerCapture(e.pointerId);
      } catch {
        // pointer capture may already be gone
      }
    };
    canvas.addEventListener('pointerup', endPan);
    canvas.addEventListener('pointerleave', endPan);

    canvas.addEventListener('dblclick', () => {
      this.scale = 1;
      this.offsetX = 0;
      this.offsetY = 0;
    });
  }

  // Maps a pointer/wheel event to internal canvas pixels (the element is CSS-scaled).
  private toCanvasCoords(e: {clientX: number; clientY: number}): {x: number; y: number} {
    const rect = this.canvas.getBoundingClientRect();
    return {
      x: (e.clientX - rect.left) * (this.canvas.width / rect.width),
      y: (e.clientY - rect.top) * (this.canvas.height / rect.height),
    };
  }

  private build(): void {
    const {width, height} = this.canvas;
    const maxRadius = Math.min(width, height) * 0.46;
    const arms = 4;
    const particleCount = 1800;

    for (let i = 0; i < particleCount; i++) {
      const arm = i % arms;
      // Bias particles outward so the arms read as arms, with tighter scatter near the core.
      const t = Math.sqrt(Math.random());
      const radius = 24 + t * maxRadius;
      const scatter = (1 - t) * 0.55 + 0.06;
      const angle = (arm / arms) * Math.PI * 2 + t * 5.6 + (Math.random() - 0.5) * scatter;
      // Hue sweeps gold core -> blue mid -> magenta rim.
      const hue = 45 + t * 255 + (Math.random() - 0.5) * 25;

      this.particles.push({
        radius,
        angle,
        size: 0.6 + Math.random() * 1.9,
        hue,
        bright: 0.35 + (1 - t) * 0.55 + Math.random() * 0.15,
      });
    }

    for (let i = 0; i < 320; i++) {
      this.stars.push({
        x: Math.random() * width,
        y: Math.random() * height,
        size: Math.random() * 1.4 + 0.2,
        phase: Math.random() * Math.PI * 2,
        speed: 0.6 + Math.random() * 2.2,
      });
    }
  }

  private loop = (): void => {
    if (!this.running) {
      return;
    }
    this.draw();
    this.raf = requestAnimationFrame(this.loop);
  };

  private draw(): void {
    const ctx = this.ctx;
    const {width, height} = this.canvas;
    const elapsed = (performance.now() - this.startMs) / 1000;

    // Own our context state every frame. WebMRecorder's keepalive shares this 2D context and leaves
    // globalAlpha at 0 (harmless for putImageData-based renderers, but it would blank our draws).
    ctx.globalAlpha = 1;

    // Trail fade in screen space (identity transform) so it always covers the viewport,
    // regardless of how the camera is panned or zoomed.
    ctx.setTransform(1, 0, 0, 1, 0, 0);
    ctx.globalCompositeOperation = 'source-over';
    ctx.fillStyle = 'rgba(3, 4, 14, 0.24)';
    ctx.fillRect(0, 0, width, height);

    // World space: the camera (pan + zoom) applies to the whole scene.
    ctx.setTransform(this.scale, 0, 0, this.scale, this.offsetX, this.offsetY);
    this.drawStars(elapsed);
    this.drawGalaxy(width, height);
    this.drawCoreGlow(width, height);

    // HUD stays pinned in screen space — the clock/readout never moves with the camera.
    ctx.setTransform(1, 0, 0, 1, 0, 0);
    this.drawClock(width, elapsed);
  }

  private drawStars(elapsed: number): void {
    const ctx = this.ctx;
    ctx.globalCompositeOperation = 'lighter';
    for (const star of this.stars) {
      const twinkle = 0.4 + 0.6 * Math.abs(Math.sin(star.phase + elapsed * star.speed));
      ctx.fillStyle = `rgba(200, 220, 255, ${twinkle * 0.5})`;
      ctx.fillRect(star.x, star.y, star.size, star.size);
    }
  }

  private drawGalaxy(width: number, height: number): void {
    const ctx = this.ctx;
    const cx = width / 2;
    const cy = height / 2;
    // Differential rotation: inner particles sweep faster than the rim.
    this.rotation += 0.0018;

    ctx.globalCompositeOperation = 'lighter';
    for (const p of this.particles) {
      const angle = p.angle + this.rotation * (60 / (p.radius + 60));
      const x = cx + Math.cos(angle) * p.radius;
      // Squash the disk vertically for a tilted, 3/4 view.
      const y = cy + Math.sin(angle) * p.radius * 0.6;

      ctx.fillStyle = `hsla(${p.hue}, 90%, 70%, ${p.bright})`;
      ctx.fillRect(x, y, p.size, p.size);
    }
  }

  private drawCoreGlow(width: number, height: number): void {
    const ctx = this.ctx;
    const cx = width / 2;
    const cy = height / 2;
    const glow = ctx.createRadialGradient(cx, cy, 0, cx, cy, 160);
    glow.addColorStop(0, 'rgba(255, 240, 200, 0.55)');
    glow.addColorStop(0.4, 'rgba(255, 180, 120, 0.18)');
    glow.addColorStop(1, 'rgba(255, 160, 100, 0)');
    ctx.globalCompositeOperation = 'lighter';
    ctx.fillStyle = glow;
    ctx.fillRect(cx - 160, cy - 160, 320, 320);
  }

  private drawClock(width: number, elapsed: number): void {
    const ctx = this.ctx;
    const now = new Date();
    const time = now.toLocaleTimeString('en-GB');
    const date = now.toLocaleDateString('en-CA');
    const rec = `REC ${this.formatElapsed(elapsed)}`;

    ctx.globalCompositeOperation = 'source-over';
    const panelW = 220;
    const panelH = 96;
    const x = width - panelW - 24;
    const y = 24;

    ctx.fillStyle = 'rgba(8, 10, 24, 0.55)';
    ctx.fillRect(x, y, panelW, panelH);
    ctx.strokeStyle = 'rgba(120, 160, 255, 0.4)';
    ctx.strokeRect(x + 0.5, y + 0.5, panelW, panelH);

    ctx.textBaseline = 'alphabetic';
    ctx.fillStyle = '#eaf2ff';
    ctx.font = '600 34px ui-monospace, "Cascadia Mono", Consolas, monospace';
    ctx.fillText(time, x + 16, y + 46);

    ctx.fillStyle = 'rgba(170, 190, 230, 0.85)';
    ctx.font = '14px ui-monospace, "Cascadia Mono", Consolas, monospace';
    ctx.fillText(date, x + 16, y + 70);

    // Blinking record dot + elapsed timer.
    if (Math.floor(elapsed * 2) % 2 === 0) {
      ctx.fillStyle = '#ff4d5e';
      ctx.beginPath();
      ctx.arc(x + 24, y + 84, 5, 0, Math.PI * 2);
      ctx.fill();
    }
    ctx.fillStyle = 'rgba(255, 120, 130, 0.95)';
    ctx.font = '13px ui-monospace, "Cascadia Mono", Consolas, monospace';
    ctx.fillText(rec, x + 38, y + 88);
  }

  private formatElapsed(seconds: number): string {
    const total = Math.floor(seconds);
    const mm = Math.floor(total / 60)
      .toString()
      .padStart(2, '0');
    const ss = (total % 60).toString().padStart(2, '0');
    return `${mm}:${ss}`;
  }
}
