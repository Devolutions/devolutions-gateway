import type { ParsedSessionRecordingLogEntry, SessionRecordingLogParseResult } from './model';

export function getSessionRecordingLogDisplayEntries(
  parseResult: Pick<SessionRecordingLogParseResult, 'entries'>,
): ParsedSessionRecordingLogEntry[] {
  return [...parseResult.entries].sort((left, right) => {
    const bySeq = left.entry.seq - right.entry.seq;
    if (bySeq !== 0) {
      return bySeq;
    }

    return left.sourceIndex - right.sourceIndex;
  });
}
