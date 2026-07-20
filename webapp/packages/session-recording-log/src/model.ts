export type SessionRecordingLogKnownEvent = 'session.start' | 'session.action' | 'session.end';

export interface SessionRecordingLogEntry {
  timestamp: string;
  seq: number;
  event: string;
  description: string;
  actor?: string;
  locale?: string;
  host?: string;
  sessionType?: string;
  object?: string;
  parameters?: Record<string, string>;
  unknownFields?: Record<string, unknown>;
}

export interface ParsedSessionRecordingLogEntry {
  entry: SessionRecordingLogEntry;
  sourceLineNumber: number;
  sourceIndex: number;
  sourceText: string;
}

export type SessionRecordingLogWarningCode =
  | 'malformed-line'
  | 'missing-session-start'
  | 'missing-session-end'
  | 'duplicate-sequence'
  | 'missing-sequence'
  | 'sequence-order-mismatch'
  | 'unknown-event-type'
  | 'invalid-field'
  | 'entry-limit-exceeded'
  | 'string-truncated'
  | 'unterminated-final-line';

export interface SessionRecordingLogWarning {
  code: SessionRecordingLogWarningCode;
  sourceLineNumber?: number;
  seq?: number;
  message: string;
}

export interface SessionRecordingLogParseResult {
  entries: ParsedSessionRecordingLogEntry[];
  warnings: SessionRecordingLogWarning[];
  completionState: 'complete' | 'ended-unexpectedly';
}

export type SessionRecordingLogCompletionState = SessionRecordingLogParseResult['completionState'];

export interface ParseSessionRecordingLogOptions {
  warnOnInvalidTimestamp?: boolean;
  maxLineLengthBytes?: number;
  maxRetainedSourceTextBytes?: number;
  maxStringLength?: number;
  maxParameterCount?: number;
  maxObjectDepth?: number;
  maxParsedEntries?: number;
  maxScannedLines?: number;
  maxMissingSequenceWarnings?: number;
  maxUnknownFieldCount?: number;
  maxWarnings?: number;
}

export interface SearchSessionRecordingLogOptions {
  limit?: number;
  caseSensitive?: boolean;
  eventTypes?: string[];
  warnings?: SessionRecordingLogWarning[];
  onlyWithWarnings?: boolean;
}

export type SearchableSessionRecordingLogField =
  | 'timestamp'
  | 'description'
  | 'object'
  | 'actor'
  | 'host'
  | 'sessionType'
  | 'parameter-key'
  | 'parameter-value';

export interface SessionRecordingLogSearchHit {
  entry: ParsedSessionRecordingLogEntry;
  sourceIndex: number;
  sourceLineNumber: number;
  matchedFields: SearchableSessionRecordingLogField[];
}

export interface SessionRecordingArtifact {
  recordingId: string;
  artifactId: string;
  fileName: string;
  /** Derived from fileName extension, not read from recording.json. */
  artifactType: string;
  contentType?: string;
  displayName: string;
  startTime?: number;
  duration?: number;
}

export interface SessionRecordingArtifactContent {
  artifact: SessionRecordingArtifact;
  blob: Blob;
  text: string;
}

// Alias preserved to match AD producer historical naming.
export type SessionRecordingLogRecord = SessionRecordingLogEntry;
export type ParsedSessionRecordingLog = SessionRecordingLogParseResult;
