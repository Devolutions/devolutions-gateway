enum ScreenScale {
  Fit = 1,
  Full = 2,
  Real = 3,
}

namespace ScreenScale {
  export function getEnumKey(value: ScreenScale): string {
    return ScreenScale[value];
  }
}
export { ScreenScale };
