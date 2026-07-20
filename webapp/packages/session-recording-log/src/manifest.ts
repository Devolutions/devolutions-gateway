export function isSessionRecordingLogFileName(fileName: string): boolean {
  if (!fileName) {
    return false;
  }

  const lowerCased = fileName.toLowerCase();
  return lowerCased.endsWith('.slog');
}
