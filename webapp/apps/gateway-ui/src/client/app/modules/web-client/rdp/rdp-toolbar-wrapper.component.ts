import { Component, EventEmitter, Input, Output, TemplateRef } from '@angular/core';
import { UserInteraction } from '@devolutions/iron-remote-desktop';
import { FloatingSessionToolbarComponent } from '@shared/components/floating-session-toolbar/floating-session-toolbar.component';
import { ToolbarAction } from '@shared/components/floating-session-toolbar/models/floating-session-toolbar-action.model';
import {
  ScreenMode,
  ToolbarFeatures,
  ToolbarInitialState,
} from '@shared/components/floating-session-toolbar/models/floating-session-toolbar-config.model';
import {
  ToolbarSessionInfo,
  ToolbarSessionInfoTemplateContext,
} from '@shared/components/floating-session-toolbar/models/session-info.model';

/**
 * Thin integration shell for the floating toolbar in RDP sessions.
 * Owns the static RDP feature config and absorbs remoteClient-direct calls
 * (Windows key, Ctrl+Alt+Del, unicode keyboard mode).
 * Everything else is bubbled up as @Output() for the protocol component to handle.
 */
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
  /** The active remote client — available after the 'ready' event fires. */
  @Input() remoteClient!: UserInteraction;

  /** Clipboard actions built by the protocol component; passed straight through. */
  @Input() actions: ToolbarAction[] = [];
  @Input() dynamicResizeSupported = true;
  @Input() sessionInfo: ToolbarSessionInfo | null = null;
  @Input() sessionInfoTemplate: TemplateRef<ToolbarSessionInfoTemplateContext> | null = null;

  /** Seed values for stateful toolbar toggles (written once on first bind). */
  @Input() initialState?: ToolbarInitialState;

  @Output() readonly sessionClose = new EventEmitter<void>();
  @Output() readonly screenModeChange = new EventEmitter<ScreenMode>();
  @Output() readonly dynamicResizeChange = new EventEmitter<boolean>();
  @Output() readonly cursorCrosshairChange = new EventEmitter<boolean>();

  /** Static RDP feature set — defined once here, never scattered across callers. */
  protected readonly features: ToolbarFeatures = {
    windowsKey: true,
    sessionInfo: true,
    ctrlAltDel: true,
    screenMode: true,
    dynamicResize: true,
    unicodeKeyboard: true,
    cursorCrosshair: true,
  };
}
