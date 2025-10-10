import { Protocol } from '@shared/enums/web-client-protocol.enum';

export const DVL_RDP_ICON = 'dvl-icon-entry-session-rdp';
export const DVL_TELNET_ICON = 'dvl-icon-entry-session-telnet';
export const DVL_SSH_ICON = 'dvl-icon-entry-session-ssh';
export const DVL_VNC_ICON = 'dvl-icon-entry-session-vnc';
export const DVL_ARD_ICON = 'dvl-icon-entry-session-apple-remote-desktop';
export const DVL_WARNING_ICON = 'dvl-icon-warning';

export const JET_RDP_URL = '/jet/rdp';
export const JET_TELNET_URL = '/jet/fwd/tcp';
export const JET_SSH_URL = '/jet/fwd/tcp';
export const JET_VNC_URL = '/jet/fwd/tcp';
export const JET_ARD_URL = '/jet/fwd/tcp';
export const JET_KDC_PROXY_URL = '/jet/KdcProxy';

export const ProtocolIconMap = {
  [Protocol.RDP]: DVL_RDP_ICON,
  [Protocol.Telnet]: DVL_TELNET_ICON,
  [Protocol.SSH]: DVL_SSH_ICON,
  [Protocol.VNC]: DVL_VNC_ICON,
  [Protocol.ARD]: DVL_ARD_ICON,
};

export const ProtocolNameToProtocolMap = {
  vnc: Protocol.VNC,
  ssh: Protocol.SSH,
  telnet: Protocol.Telnet,
  rdp: Protocol.RDP,
  ard: Protocol.ARD,
};
