import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { isSessionRecordingLogFileName } from './manifest';
import type { ParsedSessionRecordingLogEntry, SessionRecordingLogEntry, SessionRecordingLogWarning } from './model';
import { getSessionRecordingLogDisplayEntries } from './ordering';
import { parseSessionRecordingLog } from './parser';
import { searchSessionRecordingLogEntries } from './search';

function readFixture(name: string): string {
  const fixturePath = path.resolve(path.dirname(fileURLToPath(import.meta.url)), 'fixtures', name);
  return readFileSync(fixturePath, 'utf8');
}

function makeEntry(
  sourceIndex: number,
  seq: number,
  description: string,
  overrides: Partial<SessionRecordingLogEntry> = {},
): ParsedSessionRecordingLogEntry {
  return {
    sourceIndex,
    sourceLineNumber: sourceIndex + 1,
    sourceText: '{}',
    entry: {
      timestamp: `2026-07-16T10:00:0${seq}.000Z`,
      seq,
      event: 'session.action',
      description,
      ...overrides,
    },
  };
}

describe('helpers', () => {
  it('detects slog files by filename extension only', () => {
    expect(isSessionRecordingLogFileName('recording-0.slog')).toBe(true);
    expect(isSessionRecordingLogFileName('recording-0.SLOG')).toBe(true);
    expect(isSessionRecordingLogFileName('recording-0.webm')).toBe(false);
  });

  it('derives display order by seq then sourceIndex without mutating source', () => {
    const entries = [makeEntry(2, 2, 'third'), makeEntry(1, 1, 'second'), makeEntry(0, 1, 'first tie')];
    const original = entries.map((entry) => entry.sourceIndex);

    const sorted = getSessionRecordingLogDisplayEntries({ entries });

    expect(sorted.map((entry) => `${entry.entry.seq}:${entry.sourceIndex}`)).toEqual(['1:0', '1:1', '2:2']);
    expect(entries.map((entry) => entry.sourceIndex)).toEqual(original);
  });

  it('searches visible fields only and supports event/warning filters', () => {
    const entries = [
      makeEntry(0, 0, 'Renamed Object', {
        event: 'session.action',
        object: 'Help Desk Ottawa',
        actor: 'Administrator',
        host: 'IT-HELP-DC',
        sessionType: 'ADConsole',
        parameters: {
          'Members added': "Sarah O'Connor, Bob Smith",
        },
        unknownFields: {
          hidden: 'do-not-match',
        },
      }),
      makeEntry(1, 1, 'Session started', {
        event: 'session.start',
      }),
    ];

    const warnings: SessionRecordingLogWarning[] = [
      { code: 'invalid-field', sourceLineNumber: 1, seq: 0, message: 'x' },
    ];

    expect(searchSessionRecordingLogEntries(entries, "o'connor")).toHaveLength(1);
    expect(searchSessionRecordingLogEntries(entries, 'adconsole')).toHaveLength(1);
    expect(searchSessionRecordingLogEntries(entries, 'do-not-match')).toHaveLength(0);
    expect(searchSessionRecordingLogEntries(entries, 'session', { eventTypes: ['session.start'] })).toHaveLength(1);
    expect(searchSessionRecordingLogEntries(entries, '', { onlyWithWarnings: true, warnings })).toHaveLength(1);
  });

  it('supports fixture-driven ordering and search usage flow', () => {
    const parseResult = parseSessionRecordingLog(readFixture('sample-warning-linked.slog'));
    const orderedEntries = getSessionRecordingLogDisplayEntries(parseResult);

    expect(orderedEntries).toHaveLength(3);
    expect(orderedEntries.map((entry) => entry.entry.seq)).toEqual([0, 1, 2]);

    const warningOnly = searchSessionRecordingLogEntries(parseResult.entries, '', {
      onlyWithWarnings: true,
      warnings: parseResult.warnings,
    });
    const queryHits = searchSessionRecordingLogEntries(parseResult.entries, "o'connor");

    expect(parseResult.warnings.some((warning) => warning.code === 'unknown-event-type')).toBe(true);
    expect(warningOnly).toHaveLength(1);
    expect(queryHits).toHaveLength(1);
  });

  it('treats sourceLineNumber as authoritative for warning-linked filtering', () => {
    const entries = [makeEntry(0, 1, 'Original sequence'), makeEntry(1, 1, 'Duplicate sequence')];
    const warnings: SessionRecordingLogWarning[] = [
      { code: 'duplicate-sequence', sourceLineNumber: 2, seq: 1, message: 'duplicate sequence number' },
    ];

    const warningOnly = searchSessionRecordingLogEntries(entries, '', {
      onlyWithWarnings: true,
      warnings,
    });

    expect(warningOnly).toHaveLength(1);
    expect(warningOnly[0]?.sourceLineNumber).toBe(2);
  });
});
