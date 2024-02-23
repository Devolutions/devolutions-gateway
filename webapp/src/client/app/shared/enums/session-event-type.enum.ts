enum SessionEventType {
  STARTED = 0,
  TERMINATED = 1,
  ERROR = 2
}

namespace SessionEventType {
  export function getEnumKey(value: SessionEventType): string {
    return SessionEventType[value];
  }
}
export {SessionEventType};
