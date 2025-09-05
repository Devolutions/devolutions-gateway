import { SelectItemWithTooltip } from '@shared/interfaces/select-item-tooltip.interface';

enum ColorFormat {
  Default = '',
  Full = 'rgb888le',
  High = 'rgb655le',
  Medium = 'rgb332le',
  Low = 'rgb222le',
  'Very Low' = 'rgb111le',
}

enum Tooltips {
  Default = 'Color format advertised by a server',
  Full = 'True 24-bit color',
  High = 'High 16-bit color',
  Medium = '256 colors',
  Low = '64 colors',
  'Very Low' = '8 colors',
}

namespace ColorFormat {
  export function getSelectItems(): SelectItemWithTooltip[] {
    return (
      Object.entries(ColorFormat)
        // Filter out properties that are not from enum values (like function `getSelectItems`).
        .filter(([_, value]) => typeof value === 'string')
        .map(([key, value]) => ({
          label: key,
          value,
          tooltipText: Tooltips[key],
        }))
    );
  }
}

export { ColorFormat };
