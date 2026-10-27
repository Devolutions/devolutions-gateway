import {
  ToolbarModeToggle,
  ToolbarStatusBadge,
} from '@shared/components/floating-session-toolbar/models/floating-session-toolbar-config.model';
import { ArdControlMode, ArdControlModeLabels, ArdControlModes } from '@shared/interfaces/ard-control.interfaces';
import { ArdControlPending, ArdControlState } from './ard-control.model';

const ModeTooltips: Record<ArdControlMode, string> = {
  observe: "View only. Your mouse, keyboard and clipboard aren't sent to the Mac.",
  shared: 'You and the person at the Mac can both use the mouse and keyboard.',
  absolute: "Only you can use the mouse and keyboard. The Mac's own mouse and keyboard are ignored.",
};

const ModeNotAvailableTooltip = 'Not allowed by the remote computer or user';
const CurtainOnTooltip = 'Hide the curtain to change the control mode';

export function buildArdModeToggle(state: ArdControlState, pending: ArdControlPending | undefined): ToolbarModeToggle {
  return {
    ariaLabel: 'Control mode',
    options: ArdControlModes.map((mode) => {
      const available = state.availableModes.includes(mode);
      let tooltip = ModeTooltips[mode];
      if (state.curtainOn) {
        tooltip = CurtainOnTooltip;
      } else if (!available) {
        tooltip = ModeNotAvailableTooltip;
      }
      return {
        id: mode,
        label: ArdControlModeLabels[mode],
        tooltip,
        active: state.mode === mode,
        enabled: available && !state.curtainOn && !pending,
      };
    }),
  };
}

// No badge for Observe: the mode toggle already marks it active.
export function buildArdStatusBadges(state: ArdControlState): ToolbarStatusBadge[] {
  return state.curtainOn ? [{ id: 'ard-curtain-on', label: 'Curtain on', tone: 'danger' }] : [];
}
