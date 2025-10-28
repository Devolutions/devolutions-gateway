import { SelectItem } from 'primeng/api';

enum ScreenSize {
  Default = 0,
  FullScreen = 1,
  R640x480 = 2,
  R800x600 = 3,
  R1024x768 = 4,
  R1152x864 = 5,
  R1280x800 = 6,
  R1280x1024 = 7,
  R1440x900 = 8,
  R1400x1050 = 9,
  R1600x1024 = 10,
  R1600x1200 = 11,
  R1600x1280 = 12,
  R1680x1050 = 13,
  R1900x1200 = 14,
  R1920x1080 = 15,
  R1920x1200 = 16,
  R2048x1536 = 17,
  R2560x2048 = 18,
  R3200x2400 = 19,
  R3840x2400 = 20,
  Custom = 21,
}

namespace ScreenSize {
  export function getEnumRawKey(value: ScreenSize): string {
    return ScreenSize[value];
  }

  export function getEnumKey(value: ScreenSize): string {
    const key: string = ScreenSize[value];
    return key.startsWith('R') ? key.substring(1) : key;
  }

  export function getSelectItems(): SelectItem[] {
    return Object.keys(ScreenSize)
      .filter((key) => Number.isNaN(Number(key)) && typeof ScreenSize[key] === 'number')
      .map((key) => {
        let label = key;
        if (label.startsWith('R')) {
          label = label.substring(1);
        }

        const value = ScreenSize[key as keyof typeof ScreenSize];
        return { label, value };
      });
  }
}
export { ScreenSize };
