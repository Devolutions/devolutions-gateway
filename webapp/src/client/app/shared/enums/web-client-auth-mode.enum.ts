import {SelectItem} from "primeng/api";

export enum AuthMode {
  'None' = 0,
  'VNC_Password', //default
  'Username_and_Password'
}

namespace WebClientAuthMode {

  export function getEnumKey(value: AuthMode): string {
    return AuthMode[value];
  }

  export function getSelectItems(): SelectItem[] {
    return Object.keys(AuthMode)
      .filter((key) => isNaN(Number(key)) && typeof AuthMode[key as any] === 'number')
      .map((key) => {
        const label = key.replaceAll('_and_', '_&_').replaceAll('_', ' ');
        const value: AuthMode = AuthMode[key as keyof typeof AuthMode];

        return { label, value };
      });
  }

}
export {WebClientAuthMode};
