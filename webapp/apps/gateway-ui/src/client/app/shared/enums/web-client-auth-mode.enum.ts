import { SelectItem } from 'primeng/api';

export enum SshAuthMode {
  Username_and_Password = 0, //default
  Private_Key = 1,
  Keyboard_Interactive = 2,
}

namespace WebClientAuthMode {
  export function getSelectSshItems(): SelectItem[] {
    return Object.keys(SshAuthMode)
      .filter((key: string) => Number.isNaN(Number(key)) && typeof SshAuthMode[key] === 'number')
      .map((key: string): { label: string; value: SshAuthMode } => {
        const label: string = key.replaceAll('_', ' ');
        const value: SshAuthMode = SshAuthMode[key as keyof typeof SshAuthMode];

        return { label, value };
      });
  }
}
export { WebClientAuthMode };
