# `<floating-session-toolbar>`

A floating, draggable, dockable overlay toolbar for remote-session screens.  
It is a **standalone Angular component** — no module declaration needed, just import it directly.

---

## Table of contents

1. [Quick start](#quick-start)
2. [Container requirement](#container-requirement)
3. [Inputs](#inputs)
4. [Outputs](#outputs)
5. [Feature flags](#feature-flags)
6. [Wheel-speed slider](#wheel-speed-slider)
7. [Clipboard action buttons](#clipboard-action-buttons)
8. [Usage examples](#usage-examples)
9. [Built-in user controls](#built-in-user-controls)
10. [SCSS / theming](#scss--theming)
11. [File structure](#file-structure)

---

## Quick start

**Import** the component (standalone — add to `imports` array of the host module or component):

```typescript
import { FloatingSessionToolbarComponent } from '@shared/components/floating-session-toolbar/floating-session-toolbar.component';

@NgModule({
  imports: [FloatingSessionToolbarComponent, ...],
})
export class WebClientModule {}
```

**Minimal template** (close button only):

```html
<div class="my-session-container">
  <!-- session content here -->

  <floating-session-toolbar
    [features]="{}"
    (sessionClose)="endSession()">
  </floating-session-toolbar>
</div>
```

---

## Container requirement

The host element **must** have `position: relative`. The toolbar uses
`position: absolute; inset: 0` on its host so it fills and overlays the
container without consuming layout space.

```scss
.my-session-container {
  position: relative; // ← required
}
```

---

## Inputs

| Input | Type | Default | Description |
|---|---|---|---|
| `features` | `ToolbarFeatures` | `{}` | Controls which optional buttons/sections are shown. See [Feature flags](#feature-flags). |
| `theme` | `'dark' \| 'light'` | *(unset)* | When bound, the parent owns the background style and the in-toolbar "White background" toggle is **hidden**. When not bound, the user controls the background via the toggle. See [Theming](#scss--theming). |
| `initialToolbarPosition` | `ToolbarPosition` | `'top'` | Starting dock position: `'top'`, `'bottom'`, `'left'`, or `'right'`. |
| `initialAutoHide` | `boolean` | `false` | Seed the auto-hide toggle. |
| `initialDynamicResize` | `boolean` | `true` | Seed the dynamic-resize toggle (requires `features.dynamicResize`). |
| `initialUnicodeKeyboard` | `boolean` | `true` | Seed the unicode-keyboard toggle (requires `features.unicodeKeyboard`). |
| `initialCursorCrosshair` | `boolean` | `true` | Seed the cursor-crosshair toggle (requires `features.cursorCrosshair`). |
| `initialWheelSpeed` | `number` | `1` | Seed the wheel-speed slider value (requires `features.wheelSpeed`). |
| `wheelSpeedControl` | `WheelSpeedControl \| null` | `null` | Slider config (min/max/step/label). Required for the wheel-speed slider to appear. |
| `clipboardActionButtons` | `ClipboardActionButton[]` | `[]` | Action buttons appended to the dropdown Clipboard section. |

> **`initial*` inputs** write exactly **once** — on the first binding call at component
> creation. If the parent's bound expression changes later (e.g. due to change detection
> re-evaluating), the setter ignores the new value so user changes made after mount are
> never silently clobbered. This is safe because each tab owns one toolbar instance:
> when a connection closes the component is destroyed, resetting all flags for the next session.

---

## Session-scoped preferences

User preferences set inside the toolbar (dock position, white background, auto-hide)
are **session-scoped** — they live for the lifetime of that tab's connection and are
gone when the connection closes. A user who always wants the toolbar at the bottom
in white will need to set that on every new connection.

This is a product decision, not a bug. When you're ready to persist preferences,
`localStorage` keyed by protocol type would be a natural fit.

> **Future consideration — not yet implemented.** The snippet below shows what
> the wiring would look like if you added a preference service. `savePreference`
> and `loadPreference` are illustrative placeholders only.

```typescript
// Save when the user changes the dock position
(toolbarPositionChange)="savePreference('toolbarPosition', $event)"

// Restore the saved position at connection time
[initialToolbarPosition]="loadPreference('toolbarPosition') ?? 'top'"
```

---

## Outputs

| Output | Payload | When emitted |
|---|---|---|
| `sessionClose` | `void` | User clicks the close (×) button. |
| `screenModeChange` | `ScreenMode` | User clicks Minimize / Fullscreen / Fit (`'minimize' \| 'fullscreen' \| 'fit'`). |
| `toolbarPositionChange` | `ToolbarPosition` | Toolbar is docked to a new edge. |
| `windowsKeyPress` | `void` | User clicks the Windows-key button (requires `features.windowsKey`). |
| `ctrlAltDelPress` | `void` | User clicks the Ctrl+Alt+Del button (requires `features.ctrlAltDel`). |
| `dynamicResizeChange` | `boolean` | User toggles dynamic resize (requires `features.dynamicResize`). |
| `unicodeKeyboardChange` | `boolean` | User toggles unicode keyboard (requires `features.unicodeKeyboard`). |
| `cursorCrosshairChange` | `boolean` | User toggles cursor crosshair (requires `features.cursorCrosshair`). |
| `wheelSpeedChange` | `number` | User moves the wheel-speed slider (requires `features.wheelSpeed`). |

---

## Feature flags

Pass a `ToolbarFeatures` object to `[features]`. Omitted keys default to `false`.

```typescript
export interface ToolbarFeatures {
  windowsKey?:      boolean; // Windows key + Session info buttons
  ctrlAltDel?:      boolean; // Ctrl+Alt+Del button
  screenMode?:      boolean; // Minimize / Fullscreen / Fit three-way toggle
  dynamicResize?:   boolean; // Dynamic resize toggle in dropdown
  unicodeKeyboard?: boolean; // Unicode keyboard toggle in dropdown
  cursorCrosshair?: boolean; // Cursor crosshair toggle in dropdown
  wheelSpeed?:      boolean; // Wheel-speed slider in dropdown (also requires wheelSpeedControl)
}
```

**Protocol mapping:**

| Protocol | Typical `features` object |
|---|---|
| RDP | `{ windowsKey, ctrlAltDel, screenMode, dynamicResize, unicodeKeyboard, cursorCrosshair }` |
| VNC | `{ screenMode, dynamicResize, cursorCrosshair, wheelSpeed }` |
| ARD | `{ screenMode, dynamicResize, cursorCrosshair, wheelSpeed }` |
| SSH / Telnet | `{}` (close button only) |

---

## Wheel-speed slider

To show the wheel-speed slider, set **both** `features.wheelSpeed: true`
and provide a `WheelSpeedControl` object:

```typescript
export interface WheelSpeedControl {
  label?: string; // optional heading (default: 'Wheel speed')
  min:    number;
  max:    number;
  step:   number;
}
```

```html
<floating-session-toolbar
  [features]="{ wheelSpeed: true }"
  [initialWheelSpeed]="wheelSpeed"
  [wheelSpeedControl]="{ min: 1, max: 10, step: 1, label: 'Scroll speed' }"
  (wheelSpeedChange)="onWheelSpeedChange($event)">
</floating-session-toolbar>
```

---

## Clipboard action buttons

Inject arbitrary action buttons into the dropdown's **Clipboard** section.
Each button specifies its own enable/disable guard and async action:

```typescript
export interface ClipboardActionButton {
  label:   string;
  tooltip: string;
  icon:    string;           // dvl-icon CSS class, e.g. 'dvl-icon dvl-icon-copy'
  action:  () => Promise<void>;
  enabled: () => boolean;
}
```

```typescript
clipboardActionButtons: ClipboardActionButton[] = [
  {
    label:   'Copy to local clipboard',
    tooltip: 'Copy remote clipboard to local',
    icon:    'dvl-icon dvl-icon-copy',
    enabled: () => this.clipboardService.hasContent(),
    action:  () => this.clipboardService.copyToLocal(),
  },
];
```

```html
<floating-session-toolbar
  [clipboardActionButtons]="clipboardActionButtons"
  ...>
</floating-session-toolbar>
```

---

## Usage examples

### Minimal — close button only (SSH / Telnet)

```html
<div id="web-ssh-terminal-app">
  <web-ssh-gui ...></web-ssh-gui>

  <floating-session-toolbar
    [features]="{}"
    (sessionClose)="startTerminationProcess()">
  </floating-session-toolbar>
</div>
```

### Full — RDP

```html
<div class="session-rdp-container">
  <iron-remote-desktop ...></iron-remote-desktop>

  <floating-session-toolbar
    [features]="toolbarFeatures"
    [initialDynamicResize]="dynamicResizeEnabled"
    [initialUnicodeKeyboard]="useUnicodeKeyboard"
    [initialCursorCrosshair]="cursorOverrideActive"
    [clipboardActionButtons]="clipboardActionButtons"
    (windowsKeyPress)="sendWindowsKey()"
    (ctrlAltDelPress)="sendCtrlAltDel()"
    (sessionClose)="startTerminationProcess()"
    (screenModeChange)="onScreenModeChange($event)"
    (dynamicResizeChange)="onDynamicResizeChange($event)"
    (unicodeKeyboardChange)="onUnicodeKeyboardChange($event)"
    (cursorCrosshairChange)="onCursorCrosshairChange($event)">
  </floating-session-toolbar>
</div>
```

### With wheel-speed slider — VNC / ARD

```html
<div class="sessionVncContainer">
  <iron-remote-desktop ...></iron-remote-desktop>

  <floating-session-toolbar
    [features]="toolbarFeatures"
    [initialDynamicResize]="dynamicResizeEnabled"
    [initialCursorCrosshair]="cursorOverrideActive"
    [initialWheelSpeed]="wheelSpeed"
    [wheelSpeedControl]="wheelSpeedControl"
    [clipboardActionButtons]="clipboardActionButtons"
    (sessionClose)="startTerminationProcess()"
    (screenModeChange)="onScreenModeChange($event)"
    (dynamicResizeChange)="onDynamicResizeChange($event)"
    (cursorCrosshairChange)="onCursorCrosshairChange($event)"
    (wheelSpeedChange)="onWheelSpeedChange($event)">
  </floating-session-toolbar>
</div>
```

---

## Built-in user controls

These are entirely self-contained — no `@Input`/`@Output` needed:

| Control | Location | Behaviour |
|---|---|---|
| **Drag handle** | Leftmost button (move icon) | Drag the toolbar anywhere; release over a dock target to snap back to an edge. |
| **Dock targets** | Appear during drag | Four edge targets (top/bottom/left/right). Hover with cursor to highlight; release to dock. The toolbar previews the target orientation (horizontal/vertical) as soon as the cursor enters a target. |
| **Auto-hide** | Dropdown toggle | Hides toolbar when the cursor moves away; a slim edge indicator recalls it on hover. Disabled in free (dragged) mode. |
| **White background** | Dropdown toggle | Switches between the default translucent blue and a solid white pill. **Only shown when `[theme]` is not bound** — if the parent sets `[theme]`, it owns the background and this toggle is hidden. |
| **Toolbar position** | Dropdown dock icons | Dock to any of the four edges without dragging. |

---

## SCSS / theming

### Theme ownership

The `[theme]` input and the in-toolbar "White background" toggle are **mutually exclusive**:

| Scenario | Toggle visible? | Who controls the background |
|---|---|---|
| `[theme]` **not bound** | ✅ Yes | User (via dropdown toggle) |
| `[theme]="'dark'"` | ❌ Hidden | Parent — translucent blue |
| `[theme]="'light'"` | ❌ Hidden | Parent — solid white |

Use `[theme]` when the host application owns the visual theme (e.g. a global dark/light mode switch). Leave it unbound when you want users to control the toolbar background themselves.

```html
<!-- Parent-controlled: toggle hidden, toolbar always white -->
<floating-session-toolbar [theme]="'light'" ...></floating-session-toolbar>

<!-- User-controlled: toggle visible, user picks transparent or white -->
<floating-session-toolbar [features]="{}" ...></floating-session-toolbar>
```

### CSS custom properties

The component uses CSS custom properties for all colors. Override any variable
on the `floating-session-toolbar` element or any ancestor:

```scss
floating-session-toolbar {
  --toolbar-bg:     rgba(0, 0, 0, 0.6);   // dark translucent
  --toolbar-shadow: 0 4px 16px rgba(0, 0, 0, 0.2);
}
```

**Key variables (dark defaults):**

| Variable | Default | Used for |
|---|---|---|
| `--toolbar-bg` | `rgba(0, 104, 195, 0.55)` | Toolbar pill background |
| `--toolbar-icon-color` | `#ffffff` | Button icon color |
| `--toolbar-shadow` | `0 2px 10px rgba(0,0,0,0.06)` | Drop shadow |
| `--toolbar-close-bg` | `#f85454` | Close button background |

The **light theme** re-assigns these same base variables via the `.theme-light` class —
no separate `--*-light-*` variables exist. The cascade handles it automatically.

### SVG dock icons — hardcoded fill colors

The four dock-position buttons in the dropdown use inline SVG with `[attr.fill]` bindings.
CSS custom properties cannot be resolved inside SVG `fill` attributes this way, so the
active and inactive colors are hardcoded directly in the component class:

```typescript
protected readonly ICON_COLOR_ACTIVE   = '#0068C3';
protected readonly ICON_COLOR_INACTIVE = '#737373';
```

> **If the brand color changes**, update these two constants **in addition to** the
> `--toolbar-bg` / `--toolbar-icon-color` tokens in `_tokens.scss`. They are not
> linked — the compiler will not catch a mismatch.

---

## File structure

```
floating-session-toolbar/
├── floating-session-toolbar.component.ts    # Component class, all @Input/@Output
├── floating-session-toolbar.component.html  # Template
├── floating-session-toolbar.component.scss  # Entry point — @use's all partials
├── README.md                                # This file
└── styles/
    ├── _tokens.scss     # :host layout + all CSS custom property defaults
    ├── _toolbar.scss    # Pill container + dock-position variants
    ├── _buttons.scss    # Button base styles + .theme-light variable overrides
    ├── _dropdown.scss   # Overlay menu, toggles, sliders, clipboard actions
    ├── _indicator.scss  # Auto-hide edge pill
    └── _dropzones.scss  # Drag dock targets
```

