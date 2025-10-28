import { SelectItemWithTooltip } from '@shared/interfaces/select-item-tooltip.interface';

export enum Protocol {
  RDP = 0,
  Telnet = 1,
  SSH = 2,
  VNC = 3,
  ARD = 4,
}

enum Tooltips {
  'Remote Desktop Protocol' = 'RDP',
  'Teletype Network' = 'Telnet',
  'Secure Shell' = 'SSH',
  'Virtual Network Computing' = 'VNC',
  'Apple Remote Desktop' = 'ARD',
}

export type ProtocolControlMap = { [key in Protocol]?: string[] };

namespace WebClientProtocol {
  export function getEnumKey(value: Protocol): string {
    return Protocol[value];
  }

  export function getSelectItems(): SelectItemWithTooltip[] {
    // Reverse the Tooltips enum to facilitate lookup by enum name Feb 16, 2024 KAH
    const tooltipsLookup = Object.entries(Tooltips).reduce((acc, [key, value]) => {
      acc[value] = key;
      return acc;
    }, {});

    return Object.keys(Protocol)
      .filter((key) => Number.isNaN(Number(key)) && typeof Protocol[key] === 'number')
      .map((key) => {
        const label: string = key;
        const value: Protocol = Protocol[key as keyof typeof Protocol];
        const tooltipText = tooltipsLookup[key] || '';

        return { label, value, tooltipText };
      });
  }

  export function isProtocolRdp(protocol: Protocol): boolean {
    return protocol === Protocol.RDP;
  }

  export function isProtocolSsh(protocol: Protocol): boolean {
    return protocol === Protocol.SSH;
  }

  export function isProtocolVnc(protocol: Protocol): boolean {
    return protocol === Protocol.VNC;
  }

  export function isProtocolArd(protocol: Protocol): boolean {
    return protocol === Protocol.ARD;
  }
}
export { WebClientProtocol };
