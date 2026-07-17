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
const DEFAULT_MAX_WARNINGS = 10_000;

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

interface WarningCollector {
  warnings: SessionRecordingLogWarning[];
  add(warning: SessionRecordingLogWarning): void;
}

function createWarningCollector(maxWarnings: number): WarningCollector {
  const warnings: SessionRecordingLogWarning[] = [];
  let emittedTruncationWarning = false;

  return {
    warnings,
    add(warning) {
      if (warnings.length < maxWarnings) {
        warnings.push(warning);
        return;
      }

      if (emittedTruncationWarning) {
        return;
      }

      warnings.push(
        createWarning('entry-limit-exceeded', 'warning limit exceeded; additional warnings were truncated'),
      );
      emittedTruncationWarning = true;
    },
  };
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function createLineIterator(text: string): Iterable<{ line: string; sourceLineNumber: number }> {
  return {
    [Symbol.iterator](): Iterator<{ line: string; sourceLineNumber: number }> {
      let offset = 0;
      let sourceLineNumber = 1;
      let finished = false;

      return {
        next(): IteratorResult<{ line: string; sourceLineNumber: number }> {
          if (finished) {
            return { done: true, value: undefined };
          }

          if (offset >= text.length) {
            finished = true;
            return { done: true, value: undefined };
          }

          const nextNewLine = text.indexOf('\n', offset);
          if (nextNewLine === -1) {
            const line = text.slice(offset).replace(/\r$/, '');
            finished = true;
            return {
              done: false,
              value: { line, sourceLineNumber },
            };
          }

          const line = text.slice(offset, nextNewLine).replace(/\r$/, '');
          const currentLineNumber = sourceLineNumber;
          sourceLineNumber += 1;
          offset = nextNewLine + 1;
          return {
            done: false,
            value: { line, sourceLineNumber: currentLineNumber },
          };
        },
      };
    },
  };
}

function normalizeNonNegativeLimit(value: number | undefined, fallback: number): number {
  if (value === undefined || !Number.isFinite(value) || value < 0) {
    return fallback;
  }

  return Math.trunc(value);
}

function exceedsMaxLineLengthBytes(value: string, maxLineLengthBytes: number): boolean {
  let byteLength = 0;

  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);

    if (code <= 0x7f) {
      byteLength += 1;
    } else if (code <= 0x7ff) {
      byteLength += 2;
    } else if (code >= 0xd800 && code <= 0xdbff) {
      const nextCode = value.charCodeAt(index + 1);
      if (nextCode >= 0xdc00 && nextCode <= 0xdfff) {
        byteLength += 4;
        index += 1;
      } else {
        byteLength += 3;
      }
    } else {
      byteLength += 3;
    }

    if (byteLength > maxLineLengthBytes) {
      return true;
    }
  }

  return false;
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
  warningCollector: WarningCollector,
  sourceLineNumber: number,
  maxStringLength: number,
): string | null {
  if (typeof value !== 'string') {
    warningCollector.add(createWarning('invalid-field', `${field} must be a string`, { sourceLineNumber }));
    return null;
  }

  if (value.length > maxStringLength) {
    warningCollector.add(
      createWarning('string-truncated', `${field} exceeded max string length and was truncated`, { sourceLineNumber }),
    );
    return value.slice(0, maxStringLength);
  }

  return value;
}

function parseParameters(
  value: unknown,
  warningCollector: WarningCollector,
  sourceLineNumber: number,
  maxStringLength: number,
  maxParameterCount: number,
): Record<string, string> | undefined {
  if (value === undefined) {
    return undefined;
  }

  if (!isPlainObject(value)) {
    warningCollector.add(createWarning('invalid-field', 'parameters must be an object', { sourceLineNumber }));
    return undefined;
  }

  const entries = Object.entries(value);
  if (entries.length > maxParameterCount) {
    warningCollector.add(
      createWarning('entry-limit-exceeded', 'parameter count exceeded max limit', { sourceLineNumber }),
    );
  }

  const output: Record<string, string> = Object.create(null) as Record<string, string>;
  for (const [rawKey, rawValue] of entries.slice(0, maxParameterCount)) {
    let key = rawKey;
    if (rawKey.length > maxStringLength) {
      warningCollector.add(
        createWarning('string-truncated', 'parameter key exceeded max string length and was truncated', {
          sourceLineNumber,
        }),
      );
      key = rawKey.slice(0, maxStringLength);
    }

    if (typeof rawValue !== 'string') {
      warningCollector.add(createWarning('invalid-field', `parameter ${key} must be a string`, { sourceLineNumber }));
      continue;
    }

    if (Object.hasOwn(output, key)) {
      warningCollector.add(
        createWarning('invalid-field', `parameter ${key} collided after truncation and was discarded`, {
          sourceLineNumber,
        }),
      );
      continue;
    }

    if (rawValue.length > maxStringLength) {
      warningCollector.add(
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
  warningCollector: WarningCollector,
  sourceLineNumber: number,
  options: Required<
    Pick<
      ParseSessionRecordingLogOptions,
      'maxStringLength' | 'maxParameterCount' | 'warnOnInvalidTimestamp' | 'maxUnknownFieldCount'
    >
  >,
): SessionRecordingLogEntry | null {
  const timestamp = normalizeString(
    parsed.timestamp,
    'timestamp',
    warningCollector,
    sourceLineNumber,
    options.maxStringLength,
  );
  const description = normalizeString(
    parsed.description,
    'description',
    warningCollector,
    sourceLineNumber,
    options.maxStringLength,
  );
  const event = normalizeString(parsed.event, 'event', warningCollector, sourceLineNumber, options.maxStringLength);
  const seq = parsed.seq;

  if (timestamp === null || description === null || event === null) {
    return null;
  }

  if (typeof seq !== 'number' || !Number.isInteger(seq) || seq < 0) {
    warningCollector.add(createWarning('invalid-field', 'seq must be a non-negative integer', { sourceLineNumber }));
    return null;
  }
  if (!Number.isSafeInteger(seq)) {
    warningCollector.add(createWarning('invalid-field', 'seq must be a safe integer', { sourceLineNumber }));
    return null;
  }

  if (options.warnOnInvalidTimestamp && Number.isNaN(Date.parse(timestamp))) {
    warningCollector.add(
      createWarning('invalid-field', 'timestamp is not a valid date string', { sourceLineNumber, seq }),
    );
  }

  if (!KNOWN_EVENTS.has(event as SessionRecordingLogKnownEvent)) {
    warningCollector.add(
      createWarning('unknown-event-type', 'event is not one of the known lifecycle events', { sourceLineNumber, seq }),
    );
  }

  const actor =
    parsed.actor === undefined
      ? undefined
      : normalizeString(parsed.actor, 'actor', warningCollector, sourceLineNumber, options.maxStringLength);
  const locale =
    parsed.locale === undefined
      ? undefined
      : normalizeString(parsed.locale, 'locale', warningCollector, sourceLineNumber, options.maxStringLength);
  const host =
    parsed.host === undefined
      ? undefined
      : normalizeString(parsed.host, 'host', warningCollector, sourceLineNumber, options.maxStringLength);
  const sessionType =
    parsed.sessionType === undefined
      ? undefined
      : normalizeString(parsed.sessionType, 'sessionType', warningCollector, sourceLineNumber, options.maxStringLength);
  const object =
    parsed.object === undefined
      ? undefined
      : normalizeString(parsed.object, 'object', warningCollector, sourceLineNumber, options.maxStringLength);
  const parameters = parseParameters(
    parsed.parameters,
    warningCollector,
    sourceLineNumber,
    options.maxStringLength,
    options.maxParameterCount,
  );

  const unknownEntries = Object.entries(parsed).filter(([key]) => !KNOWN_FIELDS.has(key));
  if (unknownEntries.length > options.maxUnknownFieldCount) {
    warningCollector.add(
      createWarning('entry-limit-exceeded', 'unknown top-level field count exceeded max limit', { sourceLineNumber }),
    );
  }

  const unknownFields: Record<string, unknown> = Object.create(null) as Record<string, unknown>;
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
  const entries: ParsedSessionRecordingLogEntry[] = [];
  const maxLineLengthBytes = normalizeNonNegativeLimit(options?.maxLineLengthBytes, DEFAULT_MAX_LINE_LENGTH_BYTES);
  const maxStringLength = normalizeNonNegativeLimit(options?.maxStringLength, DEFAULT_MAX_STRING_LENGTH);
  const maxParameterCount = normalizeNonNegativeLimit(options?.maxParameterCount, DEFAULT_MAX_PARAMETER_COUNT);
  const maxObjectDepth = normalizeNonNegativeLimit(options?.maxObjectDepth, DEFAULT_MAX_OBJECT_DEPTH);
  const maxParsedEntries = normalizeNonNegativeLimit(options?.maxParsedEntries, DEFAULT_MAX_PARSED_ENTRIES);
  const maxScannedLines = normalizeNonNegativeLimit(options?.maxScannedLines, DEFAULT_MAX_SCANNED_LINES);
  const maxMissingSequenceWarnings = normalizeNonNegativeLimit(
    options?.maxMissingSequenceWarnings,
    DEFAULT_MAX_MISSING_SEQUENCE_WARNINGS,
  );
  const maxUnknownFieldCount = normalizeNonNegativeLimit(
    options?.maxUnknownFieldCount,
    DEFAULT_MAX_UNKNOWN_FIELD_COUNT,
  );
  const maxWarnings = normalizeNonNegativeLimit(options?.maxWarnings, DEFAULT_MAX_WARNINGS);
  const warningCollector = createWarningCollector(maxWarnings);
  const warnOnInvalidTimestamp = options?.warnOnInvalidTimestamp ?? true;
  let encounteredNonEmptyLine = false;
  let scannedLines = 0;

  const hasTrailingNewline = text.endsWith('\n');
  for (const { line, sourceLineNumber } of createLineIterator(text)) {
    scannedLines += 1;
    if (scannedLines > maxScannedLines) {
      warningCollector.add(createWarning('entry-limit-exceeded', 'scanned line limit exceeded', { sourceLineNumber }));
      break;
    }

    if (line.trim().length === 0) {
      continue;
    }

    encounteredNonEmptyLine = true;

    if (entries.length >= maxParsedEntries) {
      warningCollector.add(createWarning('entry-limit-exceeded', 'parsed entry limit exceeded', { sourceLineNumber }));
      break;
    }

    if (exceedsMaxLineLengthBytes(line, maxLineLengthBytes)) {
      warningCollector.add(createWarning('entry-limit-exceeded', 'line exceeds max byte size', { sourceLineNumber }));
      continue;
    }

    let parsed: unknown;
    try {
      parsed = JSON.parse(line);
    } catch {
      warningCollector.add(createWarning('malformed-line', 'line is not valid JSON', { sourceLineNumber }));
      continue;
    }

    if (!isPlainObject(parsed)) {
      warningCollector.add(createWarning('malformed-line', 'line JSON must be an object', { sourceLineNumber }));
      continue;
    }

    if (exceedsMaxObjectDepth(parsed, maxObjectDepth)) {
      warningCollector.add(createWarning('invalid-field', 'line object exceeds max depth', { sourceLineNumber }));
      continue;
    }

    const record = parseLineRecord(parsed, warningCollector, sourceLineNumber, {
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

  if (!hasTrailingNewline && text.length > 0) {
    warningCollector.add(createWarning('unterminated-final-line', 'final line does not end with newline'));
  }

  const seenSequences = new Set<number>();
  let previousSeq = -1;

  for (const parsedEntry of entries) {
    const seq = parsedEntry.entry.seq;

    if (seenSequences.has(seq)) {
      warningCollector.add(
        createWarning('duplicate-sequence', 'sequence number is duplicated', {
          sourceLineNumber: parsedEntry.sourceLineNumber,
          seq,
        }),
      );
    } else {
      seenSequences.add(seq);
    }

    if (seq < previousSeq) {
      warningCollector.add(
        createWarning('sequence-order-mismatch', 'file order does not match sequence order', {
          sourceLineNumber: parsedEntry.sourceLineNumber,
          seq,
        }),
      );
    }
    previousSeq = seq;
  }

  if (seenSequences.size > 0) {
    const sortedSeq = [-1, ...Array.from(seenSequences).sort((left, right) => left - right)];
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
          warningCollector.add(createWarning('missing-sequence', 'sequence number is missing', { seq }));
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
      warningCollector.add(
        createWarning(
          'entry-limit-exceeded',
          `missing sequence warnings truncated: ${missingTotal - emittedMissingWarnings} additional missing sequences`,
        ),
      );
    }
  }

  const hasSessionStart = entries.some((parsedEntry) => parsedEntry.entry.event === 'session.start');
  const hasSessionEnd = entries.some((parsedEntry) => parsedEntry.entry.event === 'session.end');

  if (entries.length > 0 && !hasSessionStart) {
    warningCollector.add(createWarning('missing-session-start', 'session.start is missing'));
  }
  if (entries.length > 0 && !hasSessionEnd) {
    warningCollector.add(createWarning('missing-session-end', 'session.end is missing'));
  }

  return {
    entries,
    warnings: warningCollector.warnings,
    completionState: !encounteredNonEmptyLine || hasSessionEnd ? 'complete' : 'ended-unexpectedly',
  };
}
