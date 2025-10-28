import { SelectItem } from 'primeng/api';

enum ResolutionQuality {
  High = 'high',
  Low = 'low',
}

namespace ResolutionQuality {
  export function getSelectItems(): SelectItem[] {
    return (
      Object.entries(ResolutionQuality)
        // Filter out properties that are not from enum values (like function `getSelectItems`).
        .filter(([_, value]) => typeof value === 'string')
        .map(([key, value]) => ({
          label: key,
          value,
        }))
    );
  }
}

export { ResolutionQuality };
