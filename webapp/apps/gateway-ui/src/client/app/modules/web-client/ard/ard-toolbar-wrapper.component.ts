import { Component, EventEmitter, Input, Output, TemplateRef } from '@angular/core';
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

/** Thin integration shell for ARD sessions. */
@Component({
  selector: 'ard-toolbar-wrapper',
  standalone: true,
  imports: [FloatingSessionToolbarComponent],
  template: `
    <floating-session-toolbar
      [features]="features"
      [initialCursorCrosshair]="initialState?.cursorCrosshair ?? true"
      [initialWheelSpeed]="initialState?.wheelSpeed ?? 1"
      [wheelSpeedControl]="wheelSpeedControl"
      [clipboardActionButtons]="actions"
      [sessionInfo]="sessionInfo"
      [sessionInfoTemplate]="sessionInfoTemplate"
      (sessionClose)="sessionClose.emit()"
      (screenModeChange)="screenModeChange.emit($event)"
      (cursorCrosshairChange)="cursorCrosshairChange.emit($event)"
      (wheelSpeedChange)="wheelSpeedChange.emit($event)">
    </floating-session-toolbar>
  `,
})
export class ArdToolbarWrapperComponent {
  @Input() actions: ToolbarAction[] = [];
  @Input() sessionInfo: ToolbarSessionInfo | null = null;
  @Input() sessionInfoTemplate: TemplateRef<ToolbarSessionInfoTemplateContext> | null = null;
  @Input() initialState?: ToolbarInitialState;
  @Input() wheelSpeedControl!: WheelSpeedControl;

  @Output() readonly sessionClose = new EventEmitter<void>();
  @Output() readonly screenModeChange = new EventEmitter<ScreenMode>();
  @Output() readonly cursorCrosshairChange = new EventEmitter<boolean>();
  @Output() readonly wheelSpeedChange = new EventEmitter<number>();

  protected readonly features: ToolbarFeatures = {
    sessionInfo: true,
    screenMode: true,
    cursorCrosshair: true,
    wheelSpeed: true,
  };
}
