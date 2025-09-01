enum SessionEventType {
  STARTED = 0,
  TERMINATED = 1,
  ERROR = 2,
  WARNING = 3,
  CLIPBOARD_REMOTE_UPDATE = 4,
}

namespace SessionEventType {
  export function getEnumKey(value: SessionEventType): string {
    return SessionEventType[value];
  }
}
export { SessionEventType };
