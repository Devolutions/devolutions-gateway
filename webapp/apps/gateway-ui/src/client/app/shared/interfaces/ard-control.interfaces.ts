/** ARD control mode as named by `iron-remote-desktop-vnc`. */
export type ArdControlMode = 'observe' | 'shared' | 'absolute';

export const DefaultArdStartMode: ArdControlMode = 'shared';

export const ArdControlModeLabels: Record<ArdControlMode, string> = {
  observe: 'Observe',
  shared: 'Shared',
  absolute: 'Exclusive',
};

/** Every mode, in the order the start-mode dropdown and the toolbar show them. */
export const ArdControlModes = Object.keys(ArdControlModeLabels) as ArdControlMode[];
