import { SelectItem } from 'primeng/api';

enum ArdQualityMode {
  Low = 'low',
  Medium = 'medium',
  High = 'high',
  Full = 'full',
  Adaptive = 'adaptive',
}

namespace ArdQualityMode {
  export function getSelectItems(): SelectItem[] {
    return (
      Object.entries(ArdQualityMode)
        // Filter out properties that are not from enum values (like function `getSelectItems`).
        .filter(([_, value]) => typeof value === 'string')
        .map(([key, value]) => ({
          label: key,
          value,
        }))
    );
  }
}

export { ArdQualityMode };
