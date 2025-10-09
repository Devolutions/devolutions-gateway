import { SelectItem } from 'primeng/api';

enum Encoding {
  Raw = 'raw',
  Zlib = 'zlib',
  Hextile = 'hextile',
  Tight = 'tight',
  TightPng = 'tight-png',
}

namespace Encoding {
  export function getSelectItems(): SelectItem[] {
    return (
      Object.entries(Encoding)
        // Filter out properties that are not from enum values (like function `getSelectItems`).
        .filter(([_, value]) => typeof value === 'string')
        .map(([key, value]) => ({
          label: key,
          value,
        }))
    );
  }

  export function getAllEncodings(): string[] {
    return (
      Object.values(Encoding)
        // Filter out properties that are not from enum values (like function `getSelectItems`).
        .filter((value) => typeof value === 'string')
    );
  }
}

export { Encoding };
