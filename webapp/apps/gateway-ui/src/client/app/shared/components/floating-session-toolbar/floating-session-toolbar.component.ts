import {
  Component,
  ElementRef,
  EventEmitter,
  HostListener,
  Input,
  OnDestroy,
  Output,
  Renderer2,
  ViewChild,
} from '@angular/core';

export type ScreenMode = 'minimize' | 'fullscreen' | 'fit';
export type ToolbarPosition = 'top' | 'bottom' | 'left' | 'right';
export type ToolbarMode = 'docked' | 'free';

export interface FreePosition {
  x: number;
  y: number;
}

/** Controls which optional buttons and dropdown sections are visible.
 *  Omitted keys are treated as false — the toolbar is minimal by default. */
export interface ToolbarFeatures {
  windowsKey?: boolean;
  ctrlAltDel?: boolean;
  screenMode?: boolean;
  dynamicResize?: boolean;
  unicodeKeyboard?: boolean;
  cursorCrosshair?: boolean;
  wheelSpeed?: boolean;
}

/** A single clipboard action entry passed in by the host protocol component. */
export interface ClipboardActionButton {
  label: string;
  tooltip: string;
  icon: string;
  action: () => Promise<void>;
  enabled: () => boolean;
}

/** Optional wheel-speed slider configuration passed by host protocol components. */
export interface WheelSpeedControl {
  label?: string;
  min: number;
  max: number;
  step: number;
}

@Component({
  selector: 'floating-session-toolbar',
  standalone: true,
  templateUrl: './floating-session-toolbar.component.html',
  styleUrls: ['./floating-session-toolbar.component.scss'],
})
export class FloatingSessionToolbarComponent implements OnDestroy {
  // ── Theme ─────────────────────────────────────────────────────────────────
  // When a parent explicitly binds [theme], it owns the background style and
  // the in-toolbar "White background" toggle is hidden.
  // When [theme] is never bound, the user controls background via the toggle.
  @Input() set theme(value: 'dark' | 'light') {
    this._theme = value;
    this.themeIsSet = true;
  }
  get theme(): 'dark' | 'light' { return this._theme; }
  private _theme: 'dark' | 'light' = 'dark';
  protected themeIsSet = false;

  // ── Inputs for initial state ──────────────────────────────────────────────
  // Each setter writes exactly once — on the first binding call at component
  // creation. Subsequent change-detection cycles that re-evaluate the parent
  // expression are ignored, so user changes made after mount are never clobbered.
  // This is safe because each tab owns one toolbar instance: when a connection
  // closes the component is destroyed, so the flags reset with the next instance.
  @Input() set initialToolbarPosition(pos: ToolbarPosition) {
    if (this._initFlags.toolbarPosition) return;
    this._initFlags.toolbarPosition = true;
    this.toolbarPosition = pos;
  }
  @Input() set initialAutoHide(value: boolean) {
    if (this._initFlags.autoHide) return;
    this._initFlags.autoHide = true;
    this.autoHide = value;
  }
  @Input() set initialDynamicResize(value: boolean) {
    if (this._initFlags.dynamicResize) return;
    this._initFlags.dynamicResize = true;
    this.dynamicResize = value;
  }
  @Input() set initialUnicodeKeyboard(value: boolean) {
    if (this._initFlags.unicodeKeyboard) return;
    this._initFlags.unicodeKeyboard = true;
    this.unicodeKeyboard = value;
  }
  @Input() set initialCursorCrosshair(value: boolean) {
    if (this._initFlags.cursorCrosshair) return;
    this._initFlags.cursorCrosshair = true;
    this.cursorCrosshair = value;
  }
  @Input() set initialWheelSpeed(value: number) {
    if (this._initFlags.wheelSpeed) return;
    this._initFlags.wheelSpeed = true;
    this.wheelSpeed = value;
  }

  // One flag per initial* input — all start false, set to true on first write.
  private readonly _initFlags = {
    toolbarPosition: false,
    autoHide:        false,
    dynamicResize:   false,
    unicodeKeyboard: false,
    cursorCrosshair: false,
    wheelSpeed:      false,
  };

  // ── Feature flags ─────────────────────────────────────────────────────────
  // A single object controls which optional buttons/sections are visible.
  // Omitted keys default to false — each protocol component opts in only to
  // the capabilities it supports.
  @Input() features: ToolbarFeatures = {};

  @Input() wheelSpeedControl: WheelSpeedControl | null = null;

  // ── Clipboard actions ─────────────────────────────────────────────────────
  @Input() clipboardActionButtons: ClipboardActionButton[] = [];

  // ── Outputs ───────────────────────────────────────────────────────────────
  @Output() readonly sessionClose = new EventEmitter<void>();
  @Output() readonly screenModeChange = new EventEmitter<ScreenMode>();
  @Output() readonly toolbarPositionChange = new EventEmitter<ToolbarPosition>();

  // Session action events — RDP (and future protocols) wire these to their
  // own methods so the toolbar stays protocol-agnostic.
  @Output() readonly windowsKeyPress = new EventEmitter<void>();
  @Output() readonly ctrlAltDelPress = new EventEmitter<void>();

  // Settings-change events — emitted whenever the user toggles a setting so
  // the host component can react (e.g. call setKeyboardUnicodeMode).
  @Output() readonly dynamicResizeChange = new EventEmitter<boolean>();
  @Output() readonly unicodeKeyboardChange = new EventEmitter<boolean>();
  @Output() readonly cursorCrosshairChange = new EventEmitter<boolean>();
  @Output() readonly wheelSpeedChange = new EventEmitter<number>();

  // Window controls three-way toggle
  screenMode: ScreenMode = 'minimize';

  // More-options dropdown
  protected showMenu = false;

  // Dropdown settings state (mirrors demo)
  autoHide = false;
  // True once the auto-hide timer fires; reset to false when the toolbar is recalled.
  private autoHideTriggered = false;

  // ── Position state ───────────────────────────────────────────────────────
  toolbarMode: ToolbarMode = 'docked';
  toolbarPosition: ToolbarPosition = 'top'; // active when mode === 'docked'
  freePosition: FreePosition | null = null; // active when mode === 'free'

  // ── Drag state ───────────────────────────────────────────────────────────
  protected isDragging = false;
  protected showDropzones = false;
  protected activeDropzone: ToolbarPosition | null = null;

  dynamicResize = true;
  unicodeKeyboard = true;
  cursorCrosshair = true;
  wheelSpeed = 1;
  whiteBackground = false;

  // ── Dock icon fill colors ─────────────────────────────────────────────────
  // SVG fill cannot consume CSS variables via attr(), so we centralise the
  // values here rather than scattering raw hex strings in the template.
  protected readonly ICON_COLOR_ACTIVE = '#0068C3';
  protected readonly ICON_COLOR_INACTIVE = '#737373';

  private hideTimeout: ReturnType<typeof setTimeout> | null = null;
  private readonly HIDE_DELAY = 500;
  private readonly PROXIMITY_DOCKED = 100;
  private readonly PROXIMITY_FREE = 200;

  // Drag timing constants
  private readonly DRAG_THRESHOLD        = 50;  // px before dropzone snapping activates
  private readonly DROPZONE_SHOW_MS      = 300; // delay before dropzones appear
  private readonly DROPZONE_ACTIVATE_MS  = 500; // delay before snapping is possible

  // Dropzone geometry — must match the CSS sizes in _dropzones.scss
  private readonly DROPZONE_H_WIDTH  = 320;
  private readonly DROPZONE_H_HEIGHT = 60;
  private readonly DROPZONE_V_WIDTH  = 60;
  private readonly DROPZONE_V_HEIGHT = 320;
  private readonly DROPZONE_MARGIN   = 8;

  // Drag tracking
  private dragStartMouse = { x: 0, y: 0 };
  private dragStartToolbar = { x: 0, y: 0 };
  private hasDraggedFar = false;
  private dropzonesActive = false;
  private autoHideBeforeDrag = false; // remembers auto-hide state so it can be restored after a snap
  private showDropzonesTimeout: ReturnType<typeof setTimeout> | null = null;
  private activateDropzonesTimeout: ReturnType<typeof setTimeout> | null = null;

  // Renderer2 unlisten functions (returned by renderer.listen)
  private unlistenDragPointermove:  (() => void) | null = null;
  private unlistenDragPointerup:    (() => void) | null = null;
  private unlistenDragPointercancel: (() => void) | null = null;
  private unlistenProximity: (() => void) | null = null;

  // Template reference — avoids repeated querySelector in hot paths (drag move, proximity check)
  @ViewChild('toolbarEl') private toolbarEl!: ElementRef<HTMLElement>;

  // ── SVG icon paths ──────────────────────────────────────────────────────────
  // Only dock-position icons live here — no dvl-icon equivalent exists for them.
  // All toolbar-button icons use dvl-icon font classes directly in the template.
  protected readonly icons = {
    dockTop:
      'M12.6667 2C13.0333 2 13.3472 2.13055 13.6083 2.39167C13.8694 2.65278 14 2.96667 14 3.33333L14 12.6667C14 13.0333 13.8694 13.3472 13.6083 13.6083C13.3472 13.8694 13.0333 14 12.6667 14L3.33333 14C2.96667 14 2.65278 13.8694 2.39167 13.6083C2.13055 13.3472 2 13.0333 2 12.6667L2 3.33333C2 2.96667 2.13056 2.65278 2.39167 2.39167C2.65278 2.13055 2.96667 2 3.33333 2L12.6667 2ZM12.6667 6.66667L3.33333 6.66667L3.33333 12.6667L12.6667 12.6667L12.6667 6.66667Z',
    dockBottom:
      'M3.33333 14C2.96667 14 2.65278 13.8694 2.39167 13.6083C2.13056 13.3472 2 13.0333 2 12.6667V3.33333C2 2.96667 2.13056 2.65278 2.39167 2.39167C2.65278 2.13056 2.96667 2 3.33333 2H12.6667C13.0333 2 13.3472 2.13056 13.6083 2.39167C13.8694 2.65278 14 2.96667 14 3.33333V12.6667C14 13.0333 13.8694 13.3472 13.6083 13.6083C13.3472 13.8694 13.0333 14 12.6667 14H3.33333ZM3.33333 9.33333H12.6667V3.33333H3.33333V9.33333Z',
    dockLeft:
      'M3.33333 14C2.96667 14 2.65278 13.8694 2.39167 13.6083C2.13056 13.3472 2 13.0333 2 12.6667V3.33333C2 2.96667 2.13056 2.65278 2.39167 2.39167C2.65278 2.13056 2.96667 2 3.33333 2H12.6667C13.0333 2 13.3472 2.13056 13.6083 2.39167C13.8694 2.65278 14 2.96667 14 3.33333V12.6667C14 13.0333 13.8694 13.3472 13.6083 13.6083C13.3472 13.8694 13.0333 14 12.6667 14H3.33333ZM6.66667 12.6667H12.6667V3.33333H6.66667V12.6667Z',
    dockRight:
      'M3.33333 14C2.96667 14 2.65278 13.8694 2.39167 13.6083C2.13056 13.3472 2 13.0333 2 12.6667V3.33333C2 2.96667 2.13056 2.65278 2.39167 2.39167C2.65278 2.13056 2.96667 2 3.33333 2H12.6667C13.0333 2 13.3472 2.13056 13.6083 2.39167C13.8694 2.65278 14 2.96667 14 3.33333V12.6667C14 13.0333 13.8694 13.3472 13.6083 13.6083C13.3472 13.8694 13.0333 14 12.6667 14H3.33333ZM9.33333 12.6667V3.33333H3.33333V12.6667H9.33333Z',
  } as const;

  constructor(
    private readonly elementRef: ElementRef,
    private readonly renderer: Renderer2,
  ) {}

  ngOnDestroy(): void {
    this.clearHideTimeout();
    this.unlistenProximity?.();
    this.cleanupDrag();
  }

  setScreenMode(mode: ScreenMode): void {
    this.screenMode = mode;
    this.screenModeChange.emit(mode);
  }

  onCloseSession(): void {
    this.sessionClose.emit();
  }

  toggleMenu(): void {
    this.showMenu = !this.showMenu;
    if (this.showMenu) {
      // Opening menu: keep toolbar visible, cancel any pending hide
      this.autoHideTriggered = false;
      this.clearHideTimeout();
    }
  }

  setToolbarPosition(pos: ToolbarPosition): void {
    this.toolbarMode = 'docked';
    this.toolbarPosition = pos;
    this.freePosition = null;
    this.showMenu = false;
    this.toolbarPositionChange.emit(pos);
  }

  toggleDynamicResize(): void {
    this.dynamicResize = !this.dynamicResize;
    this.dynamicResizeChange.emit(this.dynamicResize);
  }

  toggleUnicodeKeyboard(): void {
    this.unicodeKeyboard = !this.unicodeKeyboard;
    this.unicodeKeyboardChange.emit(this.unicodeKeyboard);
  }

  toggleCursorCrosshair(): void {
    this.cursorCrosshair = !this.cursorCrosshair;
    this.cursorCrosshairChange.emit(this.cursorCrosshair);
  }

  onWheelSpeedInput(value: string | number): void {
    const parsedValue = typeof value === 'number' ? value : Number.parseFloat(value);

    if (Number.isNaN(parsedValue)) {
      return;
    }

    this.wheelSpeed = parsedValue;
    this.wheelSpeedChange.emit(parsedValue);
  }

  /** True when at least one dropdown session-settings toggle is enabled for this protocol. */
  protected get showSessionSettings(): boolean {
    return !!(
      this.features.dynamicResize ||
      this.features.unicodeKeyboard ||
      this.features.cursorCrosshair ||
      (this.features.wheelSpeed && this.wheelSpeedControl)
    );
  }

  protected get wheelSpeedLabel(): string {
    return this.wheelSpeedControl?.label ?? 'Wheel speed';
  }

  /** True when auto-hide is on and the toolbar has timed out. */
  protected get isHidden(): boolean {
    return this.autoHide && this.autoHideTriggered;
  }

  protected get dockClass(): string {
    if (this.toolbarMode === 'free') {
      // While hovering a dropzone, preview the orientation of the target dock
      // position so the toolbar reshapes before the user releases the mouse.
      const previewVertical = this.activeDropzone !== null
        ? this.activeDropzone === 'left' || this.activeDropzone === 'right'
        : this.isVertical;
      return previewVertical ? 'dock-free dock-free-vertical' : 'dock-free';
    }
    return `dock-${this.toolbarPosition}`;
  }

  /** True whenever the toolbar should render in vertical (column) layout. */
  protected get isVertical(): boolean {
    return this.toolbarPosition === 'left' || this.toolbarPosition === 'right';
  }

  toggleWhiteBackground(): void {
    this.whiteBackground = !this.whiteBackground;
  }

  toggleAutoHide(): void {
    if (this.autoHide) {
      this.disableAutoHide();
    } else {
      this.enableAutoHide();
    }
    // Intentional: close the menu here — other toggles do NOT.
    // Reason: if auto-hide turns on while the menu is open, the showMenu guard
    // blocks the hide timer. When the user closes the menu, the toolbar vanishes
    // instantly because the cursor is already gone. Closing the menu preempts this.
    this.showMenu = false;
  }

  // ── Auto-hide listener lifecycle ─────────────────────────────────────────
  // The proximity mousemove listener is attached only while auto-hide is active.
  // This avoids a permanent document-level listener firing on every mouse move
  // for every open session tab, regardless of whether auto-hide is in use.

  private enableAutoHide(): void {
    this.autoHide = true;
    this.unlistenProximity = this.renderer.listen('document', 'mousemove', (e: MouseEvent) =>
      this.onProximityMousemove(e),
    );
  }

  private disableAutoHide(): void {
    this.autoHide = false;
    this.autoHideTriggered = false;
    this.clearHideTimeout();
    this.unlistenProximity?.();
    this.unlistenProximity = null;
  }

  onToolbarMouseEnter(): void {
    if (!this.autoHide) return;
    this.autoHideTriggered = false;
    this.clearHideTimeout();
  }

  onToolbarMouseLeave(): void {
    if (!this.autoHide || this.showMenu) return;
    this.scheduleHide();
  }

  // Position-aware proximity detection — attached/detached dynamically with auto-hide
  private onProximityMousemove(event: MouseEvent): void {
    if (this.isDragging) return;

    const shouldShow = this.isNearToolbar(event);

    if (shouldShow) {
      this.autoHideTriggered = false;
      this.clearHideTimeout();
    } else if (this.hideTimeout === null && !this.showMenu) {
      this.scheduleHide();
    }
  }

  // Close menu when clicking outside the component
  @HostListener('document:mousedown', ['$event'])
  onDocumentMousedown(event: MouseEvent): void {
    if (!this.showMenu) return; // skip DOM check when menu is already closed
    if (!this.elementRef.nativeElement.contains(event.target)) {
      this.showMenu = false;
    }
  }

  // Re-clamp free position when the browser window resizes so the toolbar
  // never gets stranded outside the (now smaller) container bounds.
  @HostListener('window:resize')
  onWindowResize(): void {
    this.reclampFreePosition();
  }

  // ── Drag initiation ──────────────────────────────────────────────────────
  // Uses Pointer Events (pointerdown/pointermove/pointerup) to support mouse,
  // touch, and stylus uniformly. setPointerCapture ensures the pointer stream
  // is not lost mid-drag on touch/stylus. isPrimary guard ignores extra fingers.
  onHandlePointerdown(event: PointerEvent): void {
    if (!event.isPrimary) return; // ignore non-primary touch points (multi-touch)
    event.preventDefault();
    event.stopPropagation();
    (event.target as HTMLElement).setPointerCapture(event.pointerId);
    this.showMenu = false; // close menu if open before drag captures all input

    const toolbarEl = this.toolbarEl?.nativeElement;
    if (!toolbarEl) return;

    const hostRect = this.getPositioningContainerRect();
    const toolbarRect: DOMRect = toolbarEl.getBoundingClientRect();

    // Record positions; toolbar coords are container-relative
    this.dragStartMouse = { x: event.clientX, y: event.clientY };
    this.dragStartToolbar = {
      x: toolbarRect.left - hostRect.left,
      y: toolbarRect.top - hostRect.top,
    };

    // Switch to free mode immediately so inline styles take over positioning
    this.toolbarMode = 'free';
    this.freePosition = { ...this.dragStartToolbar };

    // Auto-hide is incompatible with free positioning — disable it for the drag.
    // autoHideBeforeDrag remembers the state so it can be restored if the user
    // snaps back to a docked position.
    this.autoHideBeforeDrag = this.autoHide;
    if (this.autoHide) {
      this.disableAutoHide();
    }
    this.isDragging = true;
    this.hasDraggedFar = false;
    this.dropzonesActive = false;
    this.activeDropzone = null;

    // Show dropzones after timeout
    this.showDropzonesTimeout = setTimeout(() => {
      this.showDropzones = true;
    }, this.DROPZONE_SHOW_MS);

    // Allow snapping after timeout
    this.activateDropzonesTimeout = setTimeout(() => {
      this.dropzonesActive = true;
    }, this.DROPZONE_ACTIVATE_MS);

    // Attach document-level handlers via Renderer2 (runs inside Angular zone)
    this.unlistenDragPointermove = this.renderer.listen('document', 'pointermove', (e: PointerEvent) =>
      this.onDragPointermove(e),
    );
    this.unlistenDragPointerup = this.renderer.listen('document', 'pointerup', (e: PointerEvent) =>
      this.onDragPointerup(e),
    );
    // pointercancel fires when the browser takes over the pointer stream
    // (e.g. scroll gesture, page navigation, touch interrupted by a dialog).
    // Without this, cleanupDrag() would never run and showDropzones would
    // stay true into the next session, causing dropzones to appear stale.
    this.unlistenDragPointercancel = this.renderer.listen('document', 'pointercancel', (e: PointerEvent) => {
      if (e.isPrimary) this.cleanupDrag();
    });
  }

  // ── Drag move ────────────────────────────────────────────────────────────
  private onDragPointermove(event: PointerEvent): void {
    if (!event.isPrimary) return;
    const dx = event.clientX - this.dragStartMouse.x;
    const dy = event.clientY - this.dragStartMouse.y;

    const toolbarEl = this.toolbarEl?.nativeElement;
    if (!toolbarEl) return;

    this.updateFreePosition(dx, dy, toolbarEl);
    this.updateDragThreshold(dx, dy);
    this.updateActiveDropzone(event);
  }

  // Clamp the toolbar position so at least half always stays inside the container.
  private updateFreePosition(dx: number, dy: number, toolbarEl: HTMLElement): void {
    this.freePosition = this.clampPosition(
      this.dragStartToolbar.x + dx,
      this.dragStartToolbar.y + dy,
      toolbarEl,
    );
  }

  // Re-apply clamping to the current freePosition without a drag delta.
  // Called on window resize so the toolbar never strands outside the container.
  private reclampFreePosition(): void {
    if (this.toolbarMode !== 'free' || !this.freePosition) return;
    const toolbarEl = this.toolbarEl?.nativeElement;
    if (!toolbarEl) return;
    this.freePosition = this.clampPosition(this.freePosition.x, this.freePosition.y, toolbarEl);
  }

  // Shared clamping math — keeps the toolbar fully inside the host container.
  // If the toolbar is wider/taller than the container it pins to the 0 edge,
  // ensuring the drag handle is always reachable.
  private clampPosition(x: number, y: number, toolbarEl: HTMLElement): FreePosition {
    const toolbarRect = toolbarEl.getBoundingClientRect();
    const hostRect = this.getPositioningContainerRect();
    return {
      x: Math.max(0, Math.min(hostRect.width  - toolbarRect.width,  x)),
      y: Math.max(0, Math.min(hostRect.height - toolbarRect.height, y)),
    };
  }

  // Arm snapping once the drag exceeds the movement threshold.
  private updateDragThreshold(dx: number, dy: number): void {
    if (!this.hasDraggedFar && Math.sqrt(dx * dx + dy * dy) > this.DRAG_THRESHOLD) {
      this.hasDraggedFar = true;
    }
  }

  // Determine which dropzone (if any) the cursor is currently inside.
  // Uses mouse position directly so the cursor always reaches edge dropzones
  // regardless of how the toolbar body is clamped.
  private updateActiveDropzone(event: PointerEvent): void {
    if (!this.hasDraggedFar || !this.dropzonesActive) {
      this.activeDropzone = null;
      return;
    }

    const { clientX: cx, clientY: cy } = event;
    const rects = this.getDropzoneRects();
    const prevDropzone = this.activeDropzone;

    this.activeDropzone = (['top', 'bottom', 'left', 'right'] as ToolbarPosition[])
      .find(pos => {
        const r = rects[pos];
        return cx >= r.left && cx <= r.right && cy >= r.top && cy <= r.bottom;
      }) ?? null;

    // When the orientation preview flips (horizontal ↔ vertical), the toolbar's
    // rendered size changes via CSS but freePosition still reflects the old size.
    // Schedule a reclamp after Angular applies the new class so we read the correct
    // dimensions and eliminate the one-frame position jump.
    const prevVertical = prevDropzone !== null ? prevDropzone === 'left' || prevDropzone === 'right' : this.isVertical;
    const nextVertical = this.activeDropzone !== null ? this.activeDropzone === 'left' || this.activeDropzone === 'right' : this.isVertical;
    if (prevVertical !== nextVertical) {
      requestAnimationFrame(() => this.reclampFreePosition());
    }
  }

  // ── Drag end ─────────────────────────────────────────────────────────────
  private onDragPointerup(event: PointerEvent): void {
    if (!event.isPrimary) return;
    if (this.activeDropzone && this.dropzonesActive) {
      // Snap to the highlighted dock position
      this.toolbarMode = 'docked';
      this.toolbarPosition = this.activeDropzone;
      this.freePosition = null;
      this.toolbarPositionChange.emit(this.toolbarPosition);

      // Restore auto-hide if it was active before the drag — the user was just
      // repositioning, so their preference should survive the move.
      if (this.autoHideBeforeDrag) {
        this.enableAutoHide();
      }
    }
    // Free drop (no snap): toolbar stays in free mode. Auto-hide stays off —
    // it is intentionally incompatible with free positioning and is NOT restored.
    this.cleanupDrag();
  }

  // ── Dropzone geometry ─────────────────────────────────────────────────────
  private getDropzoneRects(): Record<ToolbarPosition, { left: number; top: number; right: number; bottom: number }> {
    const host = this.getPositioningContainerRect();
    return {
      top: {
        left:   host.left + (host.width - this.DROPZONE_H_WIDTH) / 2,
        top:    host.top  + this.DROPZONE_MARGIN,
        right:  host.left + (host.width + this.DROPZONE_H_WIDTH) / 2,
        bottom: host.top  + this.DROPZONE_MARGIN + this.DROPZONE_H_HEIGHT,
      },
      bottom: {
        left:   host.left   + (host.width - this.DROPZONE_H_WIDTH) / 2,
        top:    host.bottom - this.DROPZONE_MARGIN - this.DROPZONE_H_HEIGHT,
        right:  host.left   + (host.width + this.DROPZONE_H_WIDTH) / 2,
        bottom: host.bottom - this.DROPZONE_MARGIN,
      },
      left: {
        left:   host.left + this.DROPZONE_MARGIN,
        top:    host.top  + (host.height - this.DROPZONE_V_HEIGHT) / 2,
        right:  host.left + this.DROPZONE_MARGIN + this.DROPZONE_V_WIDTH,
        bottom: host.top  + (host.height + this.DROPZONE_V_HEIGHT) / 2,
      },
      right: {
        left:   host.right - this.DROPZONE_MARGIN - this.DROPZONE_V_WIDTH,
        top:    host.top   + (host.height - this.DROPZONE_V_HEIGHT) / 2,
        right:  host.right - this.DROPZONE_MARGIN,
        bottom: host.top   + (host.height + this.DROPZONE_V_HEIGHT) / 2,
      },
    };
  }

  // ── Drag cleanup ──────────────────────────────────────────────────────────
  private cleanupDrag(): void {
    this.isDragging = false;
    this.showDropzones = false;
    this.dropzonesActive = false;
    this.activeDropzone = null;
    this.hasDraggedFar = false;
    this.autoHideBeforeDrag = false;

    this.clearTimer(this.showDropzonesTimeout);
    this.showDropzonesTimeout = null;
    this.clearTimer(this.activateDropzonesTimeout);
    this.activateDropzonesTimeout = null;

    this.unlistenDragPointermove?.();
    this.unlistenDragPointermove = null;
    this.unlistenDragPointerup?.();
    this.unlistenDragPointerup = null;
    this.unlistenDragPointercancel?.();
    this.unlistenDragPointercancel = null;
  }

  private clearTimer(ref: ReturnType<typeof setTimeout> | null): void {
    if (ref !== null) clearTimeout(ref);
  }

  private isNearToolbar(event: MouseEvent): boolean {
    // Free mode: distance-based proximity from toolbar center
    if (this.toolbarMode === 'free') {
      const toolbarEl = this.toolbarEl?.nativeElement;
      if (!toolbarEl) return false;
      const rect = toolbarEl.getBoundingClientRect();
      const cx = rect.left + rect.width / 2;
      const cy = rect.top + rect.height / 2;
      return Math.sqrt((event.clientX - cx) ** 2 + (event.clientY - cy) ** 2) < this.PROXIMITY_FREE;
    }

    // Docked mode: edge-relative proximity check (uses host rect for container offset correctness)
    const hostRect = this.getPositioningContainerRect();
    const prox = this.PROXIMITY_DOCKED;

    switch (this.toolbarPosition) {
      case 'top':
        return event.clientY < hostRect.top + prox;
      case 'bottom':
        return event.clientY > hostRect.bottom - prox;
      case 'left':
        return event.clientX < hostRect.left + prox;
      case 'right':
        return event.clientX > hostRect.right - prox;
      default:
        return false;
    }
  }

  // Geometry should be based on the real session container, not the toolbar
  // host. After failed-connection form transitions the host rect can become
  // misleading, but the parent session container remains the correct anchor.
  private getPositioningContainerRect(): DOMRect {
    const parent = this.elementRef.nativeElement.parentElement as HTMLElement | null;
    return (parent ?? this.elementRef.nativeElement).getBoundingClientRect();
  }

  private scheduleHide(): void {
    this.hideTimeout = setTimeout(() => {
      this.autoHideTriggered = true;
      this.hideTimeout = null;
    }, this.HIDE_DELAY);
  }

  private clearHideTimeout(): void {
    this.clearTimer(this.hideTimeout);
    this.hideTimeout = null;
  }
}
