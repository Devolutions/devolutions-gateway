import type {
  ParsedSessionRecordingLogEntry,
  ParseSessionRecordingLogOptions,
  SessionRecordingLogEntry,
  SessionRecordingLogKnownEvent,
  SessionRecordingLogParseResult,
  SessionRecordingLogWarning,
  SessionRecordingLogWarningCode,
} from './model';

const KNOWN_EVENTS = new Set<SessionRecordingLogKnownEvent>(['session.start', 'session.action', 'session.end']);
const KNOWN_FIELDS = new Set([
  'timestamp',
  'seq',
  'event',
  'description',
  'actor',
  'locale',
  'host',
  'sessionType',
  'object',
  'parameters',
]);

const DEFAULT_MAX_LINE_LENGTH_BYTES = 256 * 1024;
const DEFAULT_MAX_STRING_LENGTH = 4096;
const DEFAULT_MAX_PARAMETER_COUNT = 200;
const DEFAULT_MAX_OBJECT_DEPTH = 8;
const DEFAULT_MAX_PARSED_ENTRIES = 10_000;
const DEFAULT_MAX_SCANNED_LINES = 20_000;
const DEFAULT_MAX_MISSING_SEQUENCE_WARNINGS = 1_000;
const DEFAULT_MAX_UNKNOWN_FIELD_COUNT = 100;
const textEncoder = new TextEncoder();

function createWarning(
  code: SessionRecordingLogWarningCode,
  message: string,
  details?: Pick<SessionRecordingLogWarning, 'sourceLineNumber' | 'seq'>,
): SessionRecordingLogWarning {
  return {
    code,
    message,
    ...details,
  };
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function exceedsMaxObjectDepth(value: unknown, maxObjectDepth: number): boolean {
  const stack: Array<{ value: unknown; depth: number }> = [{ value, depth: 1 }];

  while (stack.length > 0) {
    const current = stack.pop();
    if (!current) {
      continue;
    }

    if (current.depth > maxObjectDepth) {
      return true;
    }

    if (Array.isArray(current.value)) {
      for (const item of current.value) {
        if (isPlainObject(item) || Array.isArray(item)) {
          stack.push({ value: item, depth: current.depth + 1 });
        }
      }
      continue;
    }

    if (isPlainObject(current.value)) {
      for (const item of Object.values(current.value)) {
        if (isPlainObject(item) || Array.isArray(item)) {
          stack.push({ value: item, depth: current.depth + 1 });
        }
      }
    }
  }

  return false;
}

function normalizeString(
  value: unknown,
  field: string,
  warnings: SessionRecordingLogWarning[],
  sourceLineNumber: number,
  maxStringLength: number,
): string | null {
  if (typeof value !== 'string') {
    warnings.push(createWarning('invalid-field', `${field} must be a string`, { sourceLineNumber }));
    return null;
  }

  if (value.length > maxStringLength) {
    warnings.push(
      createWarning('string-truncated', `${field} exceeded max string length and was truncated`, { sourceLineNumber }),
    );
    return value.slice(0, maxStringLength);
  }

  return value;
}

function parseParameters(
  value: unknown,
  warnings: SessionRecordingLogWarning[],
  sourceLineNumber: number,
  maxStringLength: number,
  maxParameterCount: number,
): Record<string, string> | undefined {
  if (value === undefined) {
    return undefined;
  }

  if (!isPlainObject(value)) {
    warnings.push(createWarning('invalid-field', 'parameters must be an object', { sourceLineNumber }));
    return undefined;
  }

  const entries = Object.entries(value);
  if (entries.length > maxParameterCount) {
    warnings.push(createWarning('entry-limit-exceeded', 'parameter count exceeded max limit', { sourceLineNumber }));
  }

  const output: Record<string, string> = {};
  for (const [rawKey, rawValue] of entries.slice(0, maxParameterCount)) {
    let key = rawKey;
    if (rawKey.length > maxStringLength) {
      warnings.push(
        createWarning('string-truncated', 'parameter key exceeded max string length and was truncated', {
          sourceLineNumber,
        }),
      );
      key = rawKey.slice(0, maxStringLength);
    }

    if (typeof rawValue !== 'string') {
      warnings.push(createWarning('invalid-field', `parameter ${key} must be a string`, { sourceLineNumber }));
      continue;
    }

    if (rawValue.length > maxStringLength) {
      warnings.push(
        createWarning('string-truncated', `parameter ${key} exceeded max string length and was truncated`, {
          sourceLineNumber,
        }),
      );
      output[key] = rawValue.slice(0, maxStringLength);
      continue;
    }

    output[key] = rawValue;
  }

  return output;
}

function parseLineRecord(
  parsed: Record<string, unknown>,
  warnings: SessionRecordingLogWarning[],
  sourceLineNumber: number,
  options: Required<
    Pick<
      ParseSessionRecordingLogOptions,
      'maxStringLength' | 'maxParameterCount' | 'warnOnInvalidTimestamp' | 'maxUnknownFieldCount'
    >
  >,
): SessionRecordingLogEntry | null {
  const timestamp = normalizeString(parsed.timestamp, 'timestamp', warnings, sourceLineNumber, options.maxStringLength);
  const description = normalizeString(
    parsed.description,
    'description',
    warnings,
    sourceLineNumber,
    options.maxStringLength,
  );
  const event = normalizeString(parsed.event, 'event', warnings, sourceLineNumber, options.maxStringLength);
  const seq = parsed.seq;

  if (timestamp === null || description === null || event === null) {
    return null;
  }

  if (typeof seq !== 'number' || !Number.isInteger(seq) || seq < 0) {
    warnings.push(createWarning('invalid-field', 'seq must be a non-negative integer', { sourceLineNumber }));
    return null;
  }

  if (options.warnOnInvalidTimestamp && Number.isNaN(Date.parse(timestamp))) {
    warnings.push(createWarning('invalid-field', 'timestamp is not a valid date string', { sourceLineNumber, seq }));
  }

  if (!KNOWN_EVENTS.has(event as SessionRecordingLogKnownEvent)) {
    warnings.push(
      createWarning('unknown-event-type', 'event is not one of the known lifecycle events', { sourceLineNumber, seq }),
    );
  }

  const actor =
    parsed.actor === undefined
      ? undefined
      : normalizeString(parsed.actor, 'actor', warnings, sourceLineNumber, options.maxStringLength);
  const locale =
    parsed.locale === undefined
      ? undefined
      : normalizeString(parsed.locale, 'locale', warnings, sourceLineNumber, options.maxStringLength);
  const host =
    parsed.host === undefined
      ? undefined
      : normalizeString(parsed.host, 'host', warnings, sourceLineNumber, options.maxStringLength);
  const sessionType =
    parsed.sessionType === undefined
      ? undefined
      : normalizeString(parsed.sessionType, 'sessionType', warnings, sourceLineNumber, options.maxStringLength);
  const object =
    parsed.object === undefined
      ? undefined
      : normalizeString(parsed.object, 'object', warnings, sourceLineNumber, options.maxStringLength);
  const parameters = parseParameters(
    parsed.parameters,
    warnings,
    sourceLineNumber,
    options.maxStringLength,
    options.maxParameterCount,
  );

  const unknownEntries = Object.entries(parsed).filter(([key]) => !KNOWN_FIELDS.has(key));
  if (unknownEntries.length > options.maxUnknownFieldCount) {
    warnings.push(
      createWarning('entry-limit-exceeded', 'unknown top-level field count exceeded max limit', { sourceLineNumber }),
    );
  }

  const unknownFields: Record<string, unknown> = {};
  for (const [key, value] of unknownEntries.slice(0, options.maxUnknownFieldCount)) {
    unknownFields[key] = value;
  }

  return {
    timestamp,
    seq,
    event,
    description,
    ...(actor === null || actor === undefined ? {} : { actor }),
    ...(locale === null || locale === undefined ? {} : { locale }),
    ...(host === null || host === undefined ? {} : { host }),
    ...(sessionType === null || sessionType === undefined ? {} : { sessionType }),
    ...(object === null || object === undefined ? {} : { object }),
    ...(parameters ? { parameters } : {}),
    ...(Object.keys(unknownFields).length === 0 ? {} : { unknownFields }),
  };
}

export function parseSessionRecordingLog(
  text: string,
  options?: ParseSessionRecordingLogOptions,
): SessionRecordingLogParseResult {
  const warnings: SessionRecordingLogWarning[] = [];
  const entries: ParsedSessionRecordingLogEntry[] = [];
  const maxLineLengthBytes = options?.maxLineLengthBytes ?? DEFAULT_MAX_LINE_LENGTH_BYTES;
  const maxStringLength = options?.maxStringLength ?? DEFAULT_MAX_STRING_LENGTH;
  const maxParameterCount = options?.maxParameterCount ?? DEFAULT_MAX_PARAMETER_COUNT;
  const maxObjectDepth = options?.maxObjectDepth ?? DEFAULT_MAX_OBJECT_DEPTH;
  const maxParsedEntries = options?.maxParsedEntries ?? DEFAULT_MAX_PARSED_ENTRIES;
  const maxScannedLines = options?.maxScannedLines ?? DEFAULT_MAX_SCANNED_LINES;
  const maxMissingSequenceWarnings = options?.maxMissingSequenceWarnings ?? DEFAULT_MAX_MISSING_SEQUENCE_WARNINGS;
  const maxUnknownFieldCount = options?.maxUnknownFieldCount ?? DEFAULT_MAX_UNKNOWN_FIELD_COUNT;
  const warnOnInvalidTimestamp = options?.warnOnInvalidTimestamp ?? true;
  let scannedNonEmptyLines = 0;

  const lines = text.split(/\r?\n/);
  const hasTrailingNewline = text.endsWith('\n');
  if (!hasTrailingNewline && text.length > 0) {
    warnings.push(
      createWarning('unterminated-final-line', 'final line does not end with newline', {
        sourceLineNumber: lines.length,
      }),
    );
  }

  for (const [lineIndex, line] of lines.entries()) {
    const sourceLineNumber = lineIndex + 1;
    if (hasTrailingNewline && lineIndex === lines.length - 1 && line.length === 0) {
      continue;
    }

    if (line.trim().length === 0) {
      continue;
    }

    scannedNonEmptyLines += 1;
    if (scannedNonEmptyLines > maxScannedLines) {
      warnings.push(createWarning('entry-limit-exceeded', 'scanned line limit exceeded', { sourceLineNumber }));
      break;
    }

    if (entries.length >= maxParsedEntries) {
      warnings.push(createWarning('entry-limit-exceeded', 'parsed entry limit exceeded', { sourceLineNumber }));
      break;
    }

    if (textEncoder.encode(line).length > maxLineLengthBytes) {
      warnings.push(createWarning('entry-limit-exceeded', 'line exceeds max byte size', { sourceLineNumber }));
      continue;
    }

    let parsed: unknown;
    try {
      parsed = JSON.parse(line);
    } catch {
      warnings.push(createWarning('malformed-line', 'line is not valid JSON', { sourceLineNumber }));
      continue;
    }

    if (!isPlainObject(parsed)) {
      warnings.push(createWarning('malformed-line', 'line JSON must be an object', { sourceLineNumber }));
      continue;
    }

    if (exceedsMaxObjectDepth(parsed, maxObjectDepth)) {
      warnings.push(createWarning('invalid-field', 'line object exceeds max depth', { sourceLineNumber }));
      continue;
    }

    const record = parseLineRecord(parsed, warnings, sourceLineNumber, {
      maxStringLength,
      maxParameterCount,
      maxUnknownFieldCount,
      warnOnInvalidTimestamp,
    });
    if (!record) {
      continue;
    }

    entries.push({
      entry: record,
      sourceLineNumber,
      sourceIndex: entries.length,
      sourceText: line,
    });
  }

  const seenSequences = new Set<number>();
  let previousSeq = -1;

  for (const parsedEntry of entries) {
    const seq = parsedEntry.entry.seq;

    if (seenSequences.has(seq)) {
      warnings.push(
        createWarning('duplicate-sequence', 'sequence number is duplicated', {
          sourceLineNumber: parsedEntry.sourceLineNumber,
          seq,
        }),
      );
    } else {
      seenSequences.add(seq);
    }

    if (seq < previousSeq) {
      warnings.push(
        createWarning('sequence-order-mismatch', 'file order does not match sequence order', {
          sourceLineNumber: parsedEntry.sourceLineNumber,
          seq,
        }),
      );
    }
    previousSeq = seq;
  }

  if (seenSequences.size > 1) {
    const sortedSeq = Array.from(seenSequences).sort((left, right) => left - right);
    let missingTotal = 0;

    for (let index = 1; index < sortedSeq.length; index += 1) {
      const gap = sortedSeq[index] - sortedSeq[index - 1] - 1;
      if (gap > 0) {
        missingTotal += gap;
      }
    }

    let emittedMissingWarnings = 0;
    if (missingTotal > 0 && maxMissingSequenceWarnings > 0) {
      for (let index = 1; index < sortedSeq.length; index += 1) {
        const start = sortedSeq[index - 1] + 1;
        const end = sortedSeq[index];
        for (let seq = start; seq < end; seq += 1) {
          warnings.push(createWarning('missing-sequence', 'sequence number is missing', { seq }));
          emittedMissingWarnings += 1;
          if (emittedMissingWarnings >= maxMissingSequenceWarnings) {
            break;
          }
        }

        if (emittedMissingWarnings >= maxMissingSequenceWarnings) {
          break;
        }
      }
    }

    if (missingTotal > emittedMissingWarnings) {
      warnings.push(
        createWarning(
          'entry-limit-exceeded',
          `missing sequence warnings truncated: ${missingTotal - emittedMissingWarnings} additional gaps`,
        ),
      );
    }
  }

  const hasSessionStart = entries.some((parsedEntry) => parsedEntry.entry.event === 'session.start');
  const hasSessionEnd = entries.some((parsedEntry) => parsedEntry.entry.event === 'session.end');

  if (entries.length > 0 && !hasSessionStart) {
    warnings.push(createWarning('missing-session-start', 'session.start is missing'));
  }
  if (entries.length > 0 && !hasSessionEnd) {
    warnings.push(createWarning('missing-session-end', 'session.end is missing'));
  }

  return {
    entries,
    warnings,
    completionState: entries.length === 0 || hasSessionEnd ? 'complete' : 'ended-unexpectedly',
  };
}
