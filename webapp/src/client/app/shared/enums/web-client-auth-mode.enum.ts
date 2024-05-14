import {SelectItem} from "primeng/api";

export enum VncAuthMode {
  'None' = 0,
  'VNC_Password', //default
  'Username_and_Password'
}

export enum SshAuthMode {
  'Username_and_Password', //default
  'Private_Key'
}

namespace WebClientAuthMode {

  export function getEnumKey(value: VncAuthMode): string {
    return VncAuthMode[value];
  }

  export function getSelectVncItems(): SelectItem[] {
    return Object.keys(VncAuthMode)
      .filter((key: string) => isNaN(Number(key)) && typeof VncAuthMode[key as any] === 'number')
      .map((key: string): {label:string, value:VncAuthMode} => {
        const label: string = key.replaceAll('_', ' ').replaceAll('_', ' ');
        const value: VncAuthMode = VncAuthMode[key as keyof typeof VncAuthMode];

        return { label, value };
      });
  }

  export function getSelectSshItems(): SelectItem[] {
    return Object.keys(SshAuthMode)
      .filter((key: string) => isNaN(Number(key)) && typeof SshAuthMode[key as any] === 'number')
      .map((key: string): {label:string, value:SshAuthMode} => {
        const label: string = key.replaceAll('_', ' ');
        const value: SshAuthMode = SshAuthMode[key as keyof typeof SshAuthMode];

        return { label, value };
      });
  }

}
export {WebClientAuthMode};