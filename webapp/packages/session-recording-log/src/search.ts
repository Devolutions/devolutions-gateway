import type {
  ParsedSessionRecordingLogEntry,
  SearchableSessionRecordingLogField,
  SearchSessionRecordingLogOptions,
  SessionRecordingLogSearchHit,
} from './model';

const DEFAULT_SEARCH_LIMIT = 100;
const MAX_SEARCH_LIMIT = 1000;

function normalizeLimit(limit: number | undefined): number {
  if (!Number.isFinite(limit)) {
    return DEFAULT_SEARCH_LIMIT;
  }

  return Math.max(1, Math.min(MAX_SEARCH_LIMIT, Math.trunc(limit ?? DEFAULT_SEARCH_LIMIT)));
}

function maybeNormalize(value: string, caseSensitive: boolean): string {
  return caseSensitive ? value : value.toLowerCase();
}

function buildWarningAssociationIndex(warnings: SearchSessionRecordingLogOptions['warnings']): {
  lineNumbers: Set<number>;
  sequences: Set<number>;
} {
  const lineNumbers = new Set<number>();
  const sequences = new Set<number>();
  for (const warning of warnings ?? []) {
    if (warning.sourceLineNumber !== undefined) {
      lineNumbers.add(warning.sourceLineNumber);
    }
    if (warning.seq !== undefined) {
      sequences.add(warning.seq);
    }
  }

  return { lineNumbers, sequences };
}

function tryMatchField(
  value: string | undefined,
  query: string,
  caseSensitive: boolean,
  field: SearchableSessionRecordingLogField,
  matchedFields: Set<SearchableSessionRecordingLogField>,
): void {
  if (!value) {
    return;
  }

  const candidate = maybeNormalize(value, caseSensitive);
  if (candidate.includes(query)) {
    matchedFields.add(field);
  }
}

export function searchSessionRecordingLogEntries(
  entries: ParsedSessionRecordingLogEntry[],
  query: string,
  options?: SearchSessionRecordingLogOptions,
): SessionRecordingLogSearchHit[] {
  const trimmed = query.trim();
  const limit = normalizeLimit(options?.limit);
  const caseSensitive = options?.caseSensitive ?? false;
  const normalizedQuery = maybeNormalize(trimmed, caseSensitive);
  const eventTypes = options?.eventTypes;
  const onlyWithWarnings = options?.onlyWithWarnings ?? false;
  const warningAssociations = buildWarningAssociationIndex(options?.warnings);
  const hits: SessionRecordingLogSearchHit[] = [];

  for (const parsedEntry of entries) {
    if (eventTypes && eventTypes.length > 0 && !eventTypes.includes(parsedEntry.entry.event as never)) {
      continue;
    }

    if (
      onlyWithWarnings &&
      !warningAssociations.lineNumbers.has(parsedEntry.sourceLineNumber) &&
      !warningAssociations.sequences.has(parsedEntry.entry.seq)
    ) {
      continue;
    }

    const matchedFields = new Set<SearchableSessionRecordingLogField>();
    const entry = parsedEntry.entry;
    if (normalizedQuery.length > 0) {
      tryMatchField(entry.timestamp, normalizedQuery, caseSensitive, 'timestamp', matchedFields);
      tryMatchField(entry.description, normalizedQuery, caseSensitive, 'description', matchedFields);
      tryMatchField(entry.object, normalizedQuery, caseSensitive, 'object', matchedFields);
      tryMatchField(entry.actor, normalizedQuery, caseSensitive, 'actor', matchedFields);
      tryMatchField(entry.host, normalizedQuery, caseSensitive, 'host', matchedFields);
      tryMatchField(entry.sessionType, normalizedQuery, caseSensitive, 'sessionType', matchedFields);

      const parameters = entry.parameters ?? {};
      for (const [key, value] of Object.entries(parameters)) {
        tryMatchField(key, normalizedQuery, caseSensitive, 'parameter-key', matchedFields);
        tryMatchField(value, normalizedQuery, caseSensitive, 'parameter-value', matchedFields);
      }
    }

    if (normalizedQuery.length > 0 && matchedFields.size === 0) {
      continue;
    }

    hits.push({
      entry: parsedEntry,
      sourceIndex: parsedEntry.sourceIndex,
      sourceLineNumber: parsedEntry.sourceLineNumber,
      matchedFields: [...matchedFields],
    });

    if (hits.length >= limit) {
      break;
    }
  }

  return hits;
}
