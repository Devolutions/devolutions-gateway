import { Component, EventEmitter, Input, Output, TemplateRef } from '@angular/core';
import { UserInteraction } from '@devolutions/iron-remote-desktop';
import { FloatingSessionToolbarComponent } from '@shared/components/floating-session-toolbar/floating-session-toolbar.component';
import { ToolbarAction } from '@shared/components/floating-session-toolbar/models/floating-session-toolbar-action.model';
import {
  ScreenMode,
  ToolbarFeatures,
  ToolbarInitialState,
  WheelSpeedControl,
} from '@shared/components/floating-session-toolbar/models/floating-session-toolbar-config.model';
import {
  ToolbarSessionInfo,
  ToolbarSessionInfoTemplateContext,
} from '@shared/components/floating-session-toolbar/models/session-info.model';

/** Thin integration shell for VNC sessions. */
@Component({
  selector: 'vnc-toolbar-wrapper',
  standalone: true,
  imports: [FloatingSessionToolbarComponent],
  template: `
    <floating-session-toolbar
      [features]="features"
      [dynamicResizeSupported]="dynamicResizeSupported"
      [initialDynamicResize]="initialState?.dynamicResize ?? true"
      [initialCursorCrosshair]="initialState?.cursorCrosshair ?? true"
      [initialWheelSpeed]="initialState?.wheelSpeed ?? 1"
      [wheelSpeedControl]="wheelSpeedControl"
      [clipboardActionButtons]="actions"
      [sessionInfo]="sessionInfo"
      [sessionInfoTemplate]="sessionInfoTemplate"
      (windowsKeyPress)="remoteClient.metaKey()"
      (ctrlAltDelPress)="remoteClient.ctrlAltDel()"
      (sessionClose)="sessionClose.emit()"
      (screenModeChange)="screenModeChange.emit($event)"
      (dynamicResizeChange)="dynamicResizeChange.emit($event)"
      (cursorCrosshairChange)="cursorCrosshairChange.emit($event)"
      (wheelSpeedChange)="wheelSpeedChange.emit($event)">
    </floating-session-toolbar>
  `,
})
export class VncToolbarWrapperComponent {
  @Input() remoteClient!: UserInteraction;
  @Input() actions: ToolbarAction[] = [];
  @Input() dynamicResizeSupported = true;
  @Input() sessionInfo: ToolbarSessionInfo | null = null;
  @Input() sessionInfoTemplate: TemplateRef<ToolbarSessionInfoTemplateContext> | null = null;
  @Input() initialState?: ToolbarInitialState;
  @Input() wheelSpeedControl!: WheelSpeedControl;

  @Output() readonly sessionClose = new EventEmitter<void>();
  @Output() readonly screenModeChange = new EventEmitter<ScreenMode>();
  @Output() readonly dynamicResizeChange = new EventEmitter<boolean>();
  @Output() readonly cursorCrosshairChange = new EventEmitter<boolean>();
  @Output() readonly wheelSpeedChange = new EventEmitter<number>();

  protected readonly features: ToolbarFeatures = {
    windowsKey: true,
    sessionInfo: true,
    ctrlAltDel: true,
    screenMode: true,
    dynamicResize: true,
    cursorCrosshair: true,
    wheelSpeed: true,
  };
}
