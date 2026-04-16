# `<floating-session-toolbar>`

A floating, draggable, dockable overlay toolbar for remote-session screens.
It is a **standalone Angular component** and is now used as a **presentation-focused base component**.
In `gateway-ui`, protocol-specific integration lives in thin wrapper components (`rdp-toolbar-wrapper`, `vnc-toolbar-wrapper`, `ard-toolbar-wrapper`).

---

## Table of contents

1. [Quick start](#quick-start)
2. [Container requirement](#container-requirement)
3. [Inputs](#inputs)
4. [Outputs](#outputs)
5. [Feature flags](#feature-flags)
6. [Wheel-speed slider](#wheel-speed-slider)
7. [Clipboard action buttons](#clipboard-action-buttons)
8. [Wrapper pattern](#wrapper-pattern)
9. [Usage examples](#usage-examples)
10. [Built-in user controls](#built-in-user-controls)
11. [SCSS / theming](#scss--theming)
12. [File structure](#file-structure)
13. [Porting to another app (DVLS / Hub)](#porting-to-another-app-dvls--hub)

---

## Quick start

**Import** the component directly (no barrel file is used):

```typescript
import { FloatingSessionToolbarComponent } from '@shared/components/floating-session-toolbar/floating-session-toolbar.component';

@NgModule({
  imports: [FloatingSessionToolbarComponent],
})
export class WebClientModule {}
```

Toolbar types are imported directly from the model files:

```typescript
import {
  ToolbarFeatures,
  WheelSpeedControl,
} from '@shared/components/floating-session-toolbar/models/floating-session-toolbar-config.model';
import {
  ToolbarAction,
  ClipboardActionButton,
} from '@shared/components/floating-session-toolbar/models/floating-session-toolbar-action.model';
import {
  ToolbarSessionInfo,
  ToolbarSessionInfoRow,
  ToolbarSessionInfoTemplateContext,
} from '@shared/components/floating-session-toolbar/models/session-info.model';
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
  position: relative; // required
}
```

---

## Inputs

| Input | Type | Default | Description |
|---|---|---|---|
| `features` | `ToolbarFeatures` | `{}` | Controls which optional buttons/sections are shown. |
| `theme` | `'dark' \| 'light'` | *(unset)* | When bound, the parent owns the background style and the in-toolbar **White background** toggle is hidden. |
| `initialToolbarPosition` | `ToolbarPosition` | `'top'` | Starting dock position. |
| `initialAutoHide` | `boolean` | `false` | Seed the auto-hide toggle. |
| `initialDynamicResize` | `boolean` | `true` | Seed the dynamic-resize toggle. |
| `dynamicResizeSupported` | `boolean` | `true` | Enables/disables the **Dynamic resize** switch UI. The row stays visible when `features.dynamicResize` is true, but the toggle is disabled when this is `false`. |
| `initialUnicodeKeyboard` | `boolean` | `true` | Seed the unicode-keyboard toggle. |
| `initialCursorCrosshair` | `boolean` | `true` | Seed the cursor-crosshair toggle. |
| `initialWheelSpeed` | `number` | `1` | Seed the wheel-speed slider value. |
| `wheelSpeedControl` | `WheelSpeedControl \| null` | `null` | Slider config (min/max/step/label). |
| `clipboardActionButtons` | `ClipboardActionButton[]` | `[]` | Action buttons rendered in the dropdown Clipboard section. |
| `sessionInfo` | `ToolbarSessionInfo \| null` | `null` | Data source for the Session info popover default renderer. |
| `sessionInfoTemplate` | `TemplateRef<ToolbarSessionInfoTemplateContext> \| null` | `null` | Optional custom popover template. When omitted, the default key/value renderer is used. |
| `iconColorActive` | `string` | `'#0068C3'` | Active fill color for the dropdown dock-position SVG buttons. |
| `iconColorInactive` | `string` | `'#737373'` | Inactive fill color for the dropdown dock-position SVG buttons. |

> **`initial*` inputs** write exactly **once** — on the first binding call at component creation. Later parent expression re-evaluations are ignored so user changes made after mount are never clobbered.

---

## Session-scoped preferences

User preferences set inside the toolbar (dock position, white background, auto-hide) are **session-scoped** — they live for the lifetime of that tab's connection and are gone when the connection closes.

If you later want persistence, a host-owned service or `localStorage` keyed by protocol type is the natural next step:

```html
<floating-session-toolbar
  [initialToolbarPosition]="loadPreference('toolbarPosition') ?? 'top'"
  (toolbarPositionChange)="savePreference('toolbarPosition', $event)">
</floating-session-toolbar>
```

---

## Outputs

| Output | Payload | When emitted |
|---|---|---|
| `sessionClose` | `void` | User clicks the close button. |
| `screenModeChange` | `ScreenMode` | User clicks Minimize / Fullscreen / Fit. |
| `toolbarPositionChange` | `ToolbarPosition` | Toolbar is docked to a new edge. |
| `windowsKeyPress` | `void` | User clicks the Windows-key button. |
| `sessionInfoPress` | `void` | User clicks the Session info button. |
| `ctrlAltDelPress` | `void` | User clicks the Ctrl+Alt+Del button. |
| `dynamicResizeChange` | `boolean` | User toggles dynamic resize. |
| `unicodeKeyboardChange` | `boolean` | User toggles unicode keyboard. |
| `cursorCrosshairChange` | `boolean` | User toggles cursor crosshair. |
| `wheelSpeedChange` | `number` | User changes the wheel-speed slider. |

`sessionInfoPress` is optional and can be used for host-side telemetry; the popover UI is owned by the toolbar itself.

## Session info popover

The toolbar owns popover open/close state and default rendering. Protocol wrappers/components own the data (`sessionInfo`) and may optionally provide a custom template (`sessionInfoTemplate`).

```typescript
export type SessionInfoValue = string | number | boolean | null | undefined;

export interface ToolbarSessionInfoRow {
  id: string;
  label: string;
  value: SessionInfoValue;
  order?: number;
  hidden?: boolean;
  copyable?: boolean;
  monospace?: boolean;
  tone?: 'default' | 'muted' | 'success' | 'warning' | 'danger';
}

export interface ToolbarSessionInfo {
  title?: string;
  rows: ToolbarSessionInfoRow[];
  emptyValueText?: string;
}
```

Default renderer rules:

- Rows with `hidden === true` are not rendered.
- Rows are sorted by `order ?? Number.MAX_SAFE_INTEGER`, then original array order.
- `null`, `undefined`, and `''` display `emptyValueText ?? 'N/A'`.
- `0` and `false` are rendered as values (not treated as empty).
- Booleans render as `Yes` / `No`.
- `monospace` and `tone` are styling hints consumed by the default layout.

Example default data (`Session ID`, `Gateway URL`, `Username`):

```typescript
const sessionInfo: ToolbarSessionInfo = {
  rows: [
    { id: 'sessionId', label: 'Session ID', value: this.webSessionId, monospace: true, order: 1 },
    { id: 'gatewayUrl', label: 'Gateway URL', value: this.gatewayUrl, monospace: true, order: 2 },
    { id: 'username', label: 'Username', value: this.username, hidden: !this.username, order: 3 },
  ],
};
```

```html
<floating-session-toolbar
  [features]="{ sessionInfo: true }"
  [sessionInfo]="sessionInfo">
</floating-session-toolbar>
```

Optional custom template override:

```html
<floating-session-toolbar
  [features]="{ sessionInfo: true }"
  [sessionInfo]="sessionInfo"
  [sessionInfoTemplate]="customSessionInfoTemplate">
</floating-session-toolbar>

<ng-template #customSessionInfoTemplate let-rows="rows" let-resolveValue="resolveValue">
  @for (row of rows; track row.id) {
    <div>{{ row.label }}: {{ resolveValue(row) }}</div>
  }
</ng-template>
```

### sessionInfoTemplate (optional)

Allows a protocol or host component to override the default session info popover layout.

- **Type:** `TemplateRef<ToolbarSessionInfoTemplateContext>`
- **Optional:** Yes

By default, the toolbar renders session info using a standard key/value layout based on the provided `sessionInfo` model.

This input is reserved for cases where a protocol requires a custom layout or richer presentation that cannot be achieved using the default row-based model.

> **Note:**
> This is an advanced override mechanism.
> It is not currently used by built-in protocols.
> Prefer the default renderer unless a real customisation need exists.

---

## Feature flags

Pass a `ToolbarFeatures` object to `[features]`. Omitted keys default to `false`.

```typescript
export interface ToolbarFeatures {
  windowsKey?:      boolean;
  sessionInfo?:     boolean;
  ctrlAltDel?:      boolean;
  screenMode?:      boolean;
  dynamicResize?:   boolean;
  unicodeKeyboard?: boolean;
  cursorCrosshair?: boolean;
  wheelSpeed?:      boolean;
}
```

**Current `gateway-ui` protocol mapping:**

| Protocol | Typical `features` object |
|---|---|
| RDP | `{ windowsKey, sessionInfo, ctrlAltDel, screenMode, dynamicResize, unicodeKeyboard, cursorCrosshair }` |
| VNC | `{ windowsKey, sessionInfo, ctrlAltDel, screenMode, dynamicResize, cursorCrosshair, wheelSpeed }` |
| ARD | `{ sessionInfo, screenMode, cursorCrosshair, wheelSpeed }` |
| SSH / Telnet | `{ sessionInfo }` |

---

## Wheel-speed slider

To show the wheel-speed slider, set **both** `features.wheelSpeed: true`
and provide a `WheelSpeedControl` object:

```typescript
export interface WheelSpeedControl {
  label?: string;
  min: number;
  max: number;
  step: number;
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
The base component only renders them; the host owns the business logic.

```typescript
export interface ToolbarAction {
  id?: string; // optional; used as stable track key (fallback: label)
  label: string;
  tooltip: string;
  icon: string; // CSS class string, e.g. 'dvl-icon dvl-icon-copy'
  action: () => void | Promise<void>;
  enabled: () => boolean;
  section?: string; // optional subsection heading under Clipboard
}

export type ClipboardActionButton = ToolbarAction;
```

```typescript
const clipboardActionButtons: ClipboardActionButton[] = [
  {
    id: 'copy-local',
    section: 'Local',
    label: 'Copy to local clipboard',
    tooltip: 'Copy remote clipboard to local',
    icon: 'dvl-icon dvl-icon-copy',
    enabled: () => this.clipboardService.hasContent(),
    action: () => this.clipboardService.copyToLocal(),
  },
  {
    id: 'send-local',
    section: 'Remote',
    label: 'Send local clipboard',
    tooltip: 'Send local clipboard to remote',
    icon: 'dvl-icon dvl-icon-send',
    enabled: () => true,
    action: () => this.clipboardService.sendToRemote(),
  },
];
```

Rendering behavior:

- Actions are grouped by `section` (if provided), in first-seen order.
- Actions without a `section` are rendered in the default Clipboard block.
- Angular track key uses `id ?? label`; use unique `id` values for best DOM stability.

### Example: optional `section` grouping

You can mix grouped and ungrouped actions in one list:

```typescript
const clipboardActionButtons: ClipboardActionButton[] = [
  {
    id: 'save-clipboard',
    label: 'Save Clipboard', // no section -> default Clipboard block
    tooltip: 'Copy received clipboard content to your local clipboard.',
    icon: 'dvl-icon dvl-icon-save',
    enabled: () => this.saveRemoteClipboardButtonEnabled,
    action: () => this.saveRemoteClipboard(),
  },
  {
    id: 'send-clipboard',
    section: 'Local -> Remote',
    label: 'Send Clipboard',
    tooltip: 'Send your local clipboard content to the remote server.',
    icon: 'dvl-icon dvl-icon-send',
    enabled: () => true,
    action: () => this.sendClipboard(),
  },
  {
    id: 'clear-remote-clipboard',
    section: 'Maintenance',
    label: 'Clear Remote Clipboard',
    tooltip: 'Clear clipboard data on the remote side.',
    icon: 'dvl-icon dvl-icon-delete',
    enabled: () => true,
    action: () => this.clearRemoteClipboard(),
  },
];
```

This renders as:

- `Clipboard` (base section)
- `Save Clipboard` (default block)
- `Local -> Remote` (subsection heading)
- `Send Clipboard`
- `Maintenance` (subsection heading)
- `Clear Remote Clipboard`

```html
<floating-session-toolbar
  [features]="{}"
  [clipboardActionButtons]="clipboardActionButtons">
</floating-session-toolbar>
```

---

## Wrapper pattern

The toolbar component is now intentionally presentation-focused.
In `gateway-ui`, protocol-specific integration lives in thin standalone wrapper components:

- `rdp-toolbar-wrapper`
- `vnc-toolbar-wrapper`
- `ard-toolbar-wrapper`

Each wrapper:

- owns the static `features` object for that protocol
- passes capability flags (for example `dynamicResizeSupported`) when runtime support is negotiated after connect
- passes initial state values into `<floating-session-toolbar>`
- performs any direct `remoteClient` calls that are truly protocol-specific
- re-emits outputs still owned by the protocol component

This keeps `floating-session-toolbar` reusable across apps without packaging it and without pulling app-specific session logic into the shared UI component.

---

## Usage examples

### Minimal — close button only (SSH / Telnet)

```html
<div id="web-ssh-terminal-app">
  <web-ssh-gui></web-ssh-gui>

  <floating-session-toolbar
    [features]="{}"
    (sessionClose)="startTerminationProcess()">
  </floating-session-toolbar>
</div>
```

### Full — RDP (wrapper-based)

```html
<div class="session-rdp-container">
  <iron-remote-desktop></iron-remote-desktop>

  <rdp-toolbar-wrapper
    [remoteClient]="remoteClient"
    [actions]="clipboardActionButtons"
    [sessionInfo]="sessionInfo"
    [dynamicResizeSupported]="dynamicResizeSupported"
    [initialState]="{
      dynamicResize: dynamicResizeEnabled,
      unicodeKeyboard: useUnicodeKeyboard,
      cursorCrosshair: cursorOverrideActive
    }"
    (sessionClose)="startTerminationProcess()"
    (screenModeChange)="handleScreenModeChange($event)"
    (dynamicResizeChange)="onDynamicResizeChange($event)"
    (cursorCrosshairChange)="onCursorCrosshairChange($event)">
  </rdp-toolbar-wrapper>
</div>
```

### With wheel-speed slider — VNC (wrapper-based)

```html
<div class="session-vnc-container">
  <iron-remote-desktop></iron-remote-desktop>

  <vnc-toolbar-wrapper
    [remoteClient]="remoteClient"
    [actions]="clipboardActionButtons"
    [sessionInfo]="sessionInfo"
    [dynamicResizeSupported]="dynamicResizeSupported"
    [initialState]="{
      dynamicResize: dynamicResizeEnabled,
      cursorCrosshair: cursorOverrideActive,
      wheelSpeed: wheelSpeed
    }"
    [wheelSpeedControl]="wheelSpeedControl"
    (sessionClose)="startTerminationProcess()"
    (screenModeChange)="handleScreenModeChange($event)"
    (dynamicResizeChange)="onDynamicResizeChange($event)"
    (cursorCrosshairChange)="onCursorCrosshairChange($event)"
    (wheelSpeedChange)="onWheelSpeedChange($event)">
  </vnc-toolbar-wrapper>
</div>
```

### With wheel-speed slider — ARD (wrapper-based)

```html
<div class="session-ard-container">
  <iron-remote-desktop></iron-remote-desktop>

  <ard-toolbar-wrapper
    [actions]="clipboardActionButtons"
    [sessionInfo]="sessionInfo"
    [initialState]="{ cursorCrosshair: cursorOverrideActive, wheelSpeed: wheelSpeed }"
    [wheelSpeedControl]="wheelSpeedControl"
    (sessionClose)="startTerminationProcess()"
    (screenModeChange)="handleScreenModeChange($event)"
    (cursorCrosshairChange)="onCursorCrosshairChange($event)"
    (wheelSpeedChange)="onWheelSpeedChange($event)">
  </ard-toolbar-wrapper>
</div>
```

---

## Built-in user controls

These are entirely self-contained — no extra `@Input`/`@Output` needed:

| Control | Location | Behaviour |
|---|---|---|
| **Drag handle** | Leftmost button | Drag the toolbar anywhere; release over a dock target to snap back to an edge. |
| **Dock targets** | Appear during drag | Four edge targets (top/bottom/left/right). Hover with cursor to highlight; release to dock. |
| **Auto-hide** | Dropdown toggle | Hides the toolbar when the cursor moves away; a slim edge indicator recalls it on hover. Disabled in free mode. |
| **White background** | Dropdown toggle | Switches between the default translucent blue and a solid white pill. Hidden when `[theme]` is bound. |
| **Toolbar position** | Dropdown dock icons | Dock to any of the four edges without dragging. |

---

## SCSS / theming

### Theme ownership

The `[theme]` input and the in-toolbar **White background** toggle are mutually exclusive:

| Scenario | Toggle visible? | Who controls the background |
|---|---|---|
| `[theme]` not bound | Yes | User |
| `[theme]="'dark'"` | No | Parent |
| `[theme]="'light'"` | No | Parent |

```html
<!-- Parent-controlled -->
<floating-session-toolbar [theme]="'light'" [features]="{}"></floating-session-toolbar>

<!-- User-controlled -->
<floating-session-toolbar [features]="{}"></floating-session-toolbar>
```

### CSS custom properties

Override any variable on the `floating-session-toolbar` element or any ancestor:

```scss
floating-session-toolbar {
  --toolbar-bg: rgba(0, 0, 0, 0.6);
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
| `--toolbar-font-family` | `'Open Sans', sans-serif` | Toolbar/dropdown text |

The light theme re-assigns these same variables via `.theme-light`; there are no separate `--*-light-*` variables.

### SVG dock icons — configurable fill colors

The four dock-position buttons in the dropdown use inline SVG with `[attr.fill]` bindings.
Because CSS custom properties cannot be resolved there directly, the active and inactive colors are exposed as component inputs:

```typescript
class ExampleToolbarHost {
  iconColorActive = '#0068C3';
  iconColorInactive = '#737373';
}
```

---

## File structure

```text
floating-session-toolbar/
├── floating-session-toolbar.component.ts        # Base presentational component
├── floating-session-toolbar.component.html      # Template
├── floating-session-toolbar.component.scss      # Entry point — @use's all partials
├── README.md                                    # This file
├── models/
│   ├── floating-session-toolbar-config.model.ts # Toolbar types/config models
│   ├── floating-session-toolbar-action.model.ts # ToolbarAction + ClipboardActionButton alias
│   └── session-info.model.ts                    # Session info popover row/template models
├── utils/
│   └── floating-session-toolbar.utils.ts        # Drag/drop geometry helpers
└── styles/
    ├── _tokens.scss                             # :host layout + CSS custom property defaults
    ├── _floating-session-toolbar-theme.scss     # centralised .theme-light overrides
    ├── _toolbar.scss                            # Pill container + dock-position variants
    ├── _buttons.scss                            # Button base styles
    ├── _dropdown.scss                           # Overlay menu, toggles, sliders, clipboard actions
    ├── _indicator.scss                          # Auto-hide edge pill
    └── _dropzones.scss                          # Drag dock targets
```

Current protocol-specific wrappers live outside this folder under:

```text
modules/web-client/
├── rdp/rdp-toolbar-wrapper.component.ts
├── vnc/vnc-toolbar-wrapper.component.ts
└── ard/ard-toolbar-wrapper.component.ts
```

---

## Porting to another app (DVLS / Hub)

The toolbar and its models have **zero app-specific dependencies** — no Angular module references, no injected services, no `gateway-ui` internals.
The steps below describe a clean adoption in a separate Angular app.

### Step 1 — Copy the component folder

Copy the entire `floating-session-toolbar/` folder into the target app's shared component directory:

```text
floating-session-toolbar/
├── floating-session-toolbar.component.ts
├── floating-session-toolbar.component.html
├── floating-session-toolbar.component.scss
├── models/
│   ├── floating-session-toolbar-config.model.ts
│   ├── floating-session-toolbar-action.model.ts
│   └── session-info.model.ts
├── utils/
│   └── floating-session-toolbar.utils.ts
└── styles/
    ├── _tokens.scss
    ├── _floating-session-toolbar-theme.scss
    ├── _toolbar.scss
    ├── _buttons.scss
    ├── _dropdown.scss
    ├── _indicator.scss
    └── _dropzones.scss
```

Do **not** copy the wrappers (`rdp-toolbar-wrapper`, etc.) — you will write new, app-tailored ones in Step 4.

### Step 2 — Update host-side imports

The **copied folder itself requires no import changes.** Every file inside
`floating-session-toolbar/` uses only relative paths (`./models/...`,
`./utils/...`) and framework imports (`@angular/common`). There are zero
`@shared/...` references inside the folder.

What *does* need updating are the **host-side files outside the folder** that
import the toolbar — your wrappers, protocol components, and any file that
references a toolbar type:

```typescript
// Before (gateway-ui alias)
import { FloatingSessionToolbarComponent }
  from '@shared/components/floating-session-toolbar/floating-session-toolbar.component';

import { ToolbarFeatures, WheelSpeedControl }
  from '@shared/components/floating-session-toolbar/models/floating-session-toolbar-config.model';

// After (replace with your app's alias or a relative path)
import { FloatingSessionToolbarComponent }
  from '<your-path>/floating-session-toolbar.component';

import { ToolbarFeatures, WheelSpeedControl }
  from '<your-path>/models/floating-session-toolbar-config.model';
```

If your app exposes a `@shared` path alias that resolves to the same location
you copied the folder into, no changes at all are needed.

```json
// tsconfig.json — example alias that requires no import changes
{
  "compilerOptions": {
    "paths": {
      "@shared/*": ["src/app/shared/*"]
    }
  }
}
```


### Step 3 — Register the font

The toolbar uses `'Open Sans', sans-serif` via the `--toolbar-font-family` CSS custom property.
If the target app does not already load Open Sans, add it to the global stylesheet:

```css
@import url('https://fonts.googleapis.com/css2?family=Open+Sans:wght@400;600&display=swap');
```

Or override the variable to use a font already available in the target app:

```scss
floating-session-toolbar {
  --toolbar-font-family: 'Your App Font', sans-serif;
}
```

### Step 4 — Create protocol wrappers

Create a thin wrapper component for each protocol. Use the `gateway-ui` wrappers as the template.
Each wrapper:

- declares the static `features` object for that protocol
- passes `initialState` values as template bindings
- calls `remoteClient` methods directly (Windows key, Ctrl+Alt+Del, unicode mode)
- re-emits all other outputs for the session component to handle

> **Do not inject app services into wrappers.** DVLS, Hub, and `gateway-ui` diverge significantly
> in session lifecycle, authentication, and analytics services. Service logic belongs in the
> session component layer, not in the wrappers.

**Minimal wrapper skeleton (adapt imports to your path alias):**

```typescript
import { Component, EventEmitter, Input, Output, TemplateRef } from '@angular/core';
import { UserInteraction } from '@devolutions/iron-remote-desktop';
import { FloatingSessionToolbarComponent } from '<your-path>/floating-session-toolbar.component';
import {
  ScreenMode,
  ToolbarFeatures,
  ToolbarInitialState,
} from '<your-path>/models/floating-session-toolbar-config.model';
import { ToolbarAction } from '<your-path>/models/floating-session-toolbar-action.model';
import {
  ToolbarSessionInfo,
  ToolbarSessionInfoTemplateContext,
} from '<your-path>/models/session-info.model';

@Component({
  selector: 'rdp-toolbar-wrapper',
  standalone: true,
  imports: [FloatingSessionToolbarComponent],
  template: `
    <floating-session-toolbar
      [features]="features"
      [dynamicResizeSupported]="dynamicResizeSupported"
      [initialDynamicResize]="initialState?.dynamicResize ?? true"
      [initialUnicodeKeyboard]="initialState?.unicodeKeyboard ?? true"
      [initialCursorCrosshair]="initialState?.cursorCrosshair ?? true"
      [clipboardActionButtons]="actions"
      [sessionInfo]="sessionInfo"
      [sessionInfoTemplate]="sessionInfoTemplate"
      (windowsKeyPress)="remoteClient.metaKey()"
      (ctrlAltDelPress)="remoteClient.ctrlAltDel()"
      (unicodeKeyboardChange)="remoteClient.setKeyboardUnicodeMode($event)"
      (sessionClose)="sessionClose.emit()"
      (screenModeChange)="screenModeChange.emit($event)"
      (dynamicResizeChange)="dynamicResizeChange.emit($event)"
      (cursorCrosshairChange)="cursorCrosshairChange.emit($event)">
    </floating-session-toolbar>
  `,
})
export class RdpToolbarWrapperComponent {
  @Input() remoteClient!: UserInteraction;
  @Input() actions: ToolbarAction[] = [];
  @Input() dynamicResizeSupported = true;
  @Input() initialState?: ToolbarInitialState;
  @Input() sessionInfo: ToolbarSessionInfo | null = null;
  @Input() sessionInfoTemplate: TemplateRef<ToolbarSessionInfoTemplateContext> | null = null;

  @Output() readonly sessionClose          = new EventEmitter<void>();
  @Output() readonly screenModeChange      = new EventEmitter<ScreenMode>();
  @Output() readonly dynamicResizeChange   = new EventEmitter<boolean>();
  @Output() readonly cursorCrosshairChange = new EventEmitter<boolean>();

  protected readonly features: ToolbarFeatures = {
    windowsKey:      true,
    sessionInfo:     true,
    ctrlAltDel:      true,
    screenMode:      true,
    dynamicResize:   true,
    unicodeKeyboard: true,
    cursorCrosshair: true,
  };
}
```

For VNC add `wheelSpeedControl: WheelSpeedControl` input and `wheelSpeedChange` output.
For ARD omit `windowsKey`, `ctrlAltDel`, and `unicodeKeyboard` from `features`.

> **`initialState` must not be a `readonly` class field initialized at declaration time.**
> Reading `@Input()` values at field initialization is unsafe in Angular.
> Build the object inline in the template binding as shown, not in the component body.

### Step 5 — Clipboard integration

In `gateway-ui`, clipboard handling is centralized in `DesktopWebClientBaseComponent.setupClipboardHandling()`.
It builds the `clipboardActionButtons` array using **only browser-standard APIs** (`window.isSecureContext`,
`navigator.clipboard`) — there are no app-specific services involved.

**If your app already extends `DesktopWebClientBaseComponent`** (copied from `gateway-ui`), call
`this.setupClipboardHandling(autoClipboard)` inside your session-ready handler. The base class handles
the rest:

```typescript
// Inside your protocol component, after the remote client is ready:
this.setupClipboardHandling(this.formData?.autoClipboard);
// this.clipboardActionButtons is now ready to pass to `[actions]`
```

**If your app does NOT use `DesktopWebClientBaseComponent`**, replicate the method in your own base or
session component. The logic is portable — the full implementation is in
`desktop-web-client-base.component.ts` under `shared/bases/`. The only external references are:

- `this.remoteClient` — the `UserInteraction` instance from `@devolutions/iron-remote-desktop`
- `this.saveRemoteClipboardButtonEnabled` — a boolean flag toggled by the `onClipboardRemoteUpdateCallback`
- `this.saveRemoteClipboard()` / `this.sendClipboard()` — thin wrappers around `remoteClient` calls

Copy those four pieces verbatim into your own session base and the method will work unchanged.

### Step 6 — Screen mode / fullscreen

`gateway-ui` centralizes screen mode handling in `DesktopWebClientBaseComponent.handleScreenModeChange()`:

```typescript
handleScreenModeChange(mode: ScreenMode): void {
  switch (mode) {
    case 'fullscreen': this.toggleFullscreen();        break;
    case 'fit':        this.scaleTo(ScreenScale.Fit);  break;
    case 'minimize':   this.scaleTo(ScreenScale.Real); break;
  }
}
```

If you are not copying the base class, add this method directly to the session component that receives the
`(screenModeChange)` output from the wrapper, and implement `toggleFullscreen()` and `scaleTo()` to
match your app's fullscreen/scale APIs.

### Step 7 — Register wrappers in your module

Each wrapper is a **standalone component**, so registration is a single line:

```typescript
@NgModule({
  imports: [
    RdpToolbarWrapperComponent,
    VncToolbarWrapperComponent,
    ArdToolbarWrapperComponent,
  ],
})
export class YourSessionModule {}
```

Or import directly into a standalone host component:

```typescript
@Component({
  standalone: true,
  imports: [RdpToolbarWrapperComponent],
})
export class YourRdpSessionComponent {}
```

### Step 8 — Validate with RDP first

The RDP wrapper is the simplest (no wheel speed, all features explicit).
Wire it up end-to-end in one protocol before building VNC and ARD wrappers.
Surface any API incompatibilities at the smallest possible scope.

### Checklist

- [ ] `floating-session-toolbar/` folder copied and SCSS partials intact
- [ ] `@shared/...` imports replaced with app-specific alias or relative paths
- [ ] Font available (`Open Sans` or `--toolbar-font-family` overridden)
- [ ] One wrapper per protocol created (no services injected)
- [ ] `clipboardActionButtons` built by the session component and passed to `[actions]`
- [ ] `handleScreenModeChange()` (or equivalent) wired to `(screenModeChange)` output
- [ ] Wrappers registered in module or imported by standalone host components
- [ ] RDP validated end-to-end before building VNC / ARD wrappers

