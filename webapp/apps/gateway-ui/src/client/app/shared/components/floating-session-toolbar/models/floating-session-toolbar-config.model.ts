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
  sessionInfo?: boolean;
  ctrlAltDel?: boolean;
  screenMode?: boolean;
  dynamicResize?: boolean;
  unicodeKeyboard?: boolean;
  cursorCrosshair?: boolean;
  wheelSpeed?: boolean;
}

/** Seed values written exactly once at component creation.
 *  Subsequent change-detection cycles that re-evaluate the parent expression
 *  are ignored so user changes made after mount are never clobbered. */
export interface ToolbarInitialState {
  position?: ToolbarPosition;
  autoHide?: boolean;
  dynamicResize?: boolean;
  unicodeKeyboard?: boolean;
  cursorCrosshair?: boolean;
  wheelSpeed?: number;
}

/** Optional wheel-speed slider configuration passed by host protocol components. */
export interface WheelSpeedControl {
  label?: string;
  min: number;
  max: number;
  step: number;
}

/** Single consolidated config object — forward-looking type for future API migration.
 *  The component still accepts individual @Input() fields; this type is used by
 *  wrapper components and will replace the scattered inputs in a later PR. */
export interface ToolbarConfig {
  features: ToolbarFeatures;
  initialState?: ToolbarInitialState;
  wheelSpeedControl?: WheelSpeedControl | null;
}
