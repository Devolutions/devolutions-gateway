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

const ModeIcons: Record<ArdControlMode, string> = {
  observe: 'dvl-icon dvl-icon-watching',
  shared: 'dvl-icon dvl-icon-cursor',
  absolute: 'dvl-icon dvl-icon-user-locked',
};

const ModeNotAvailableTooltip = 'Not allowed by the remote computer or user';
const CurtainOnTooltip = 'Hide the curtain to change the control mode';

export function buildArdModeToggle(state: ArdControlState, pending: ArdControlPending | undefined): ToolbarModeToggle {
  return {
    ariaLabel: 'Control mode',
    options: ArdControlModes.map((mode) => {
      const available = state.availableModes.includes(mode);
      const label = ArdControlModeLabels[mode];
      let description = ModeTooltips[mode];
      if (state.curtainOn) {
        description = CurtainOnTooltip;
      } else if (!available) {
        description = ModeNotAvailableTooltip;
      }
      return {
        id: mode,
        label,
        icon: ModeIcons[mode],
        // The button is icon-only, so the tooltip leads with the mode name.
        tooltip: `${label}: ${description}`,
        active: state.mode === mode,
        enabled: available && !state.curtainOn && !pending,
      };
    }),
  };
}

// No badge for Observe: the mode toggle already marks it active.
export function buildArdStatusBadges(state: ArdControlState): ToolbarStatusBadge[] {
  return state.curtainOn
    ? [
        {
          id: 'ard-curtain-on',
          label: 'Curtain on',
          icon: 'dvl-icon dvl-icon-wayk-session-off',
          tooltip:
            'Curtain on: the person at the Mac sees your message instead of their screen. To remove it, choose Hide curtain in the ⋮ menu.',
          tone: 'danger',
        },
      ]
    : [];
}
