import { describe, expect, it } from 'vitest';
import { parseSessionRecordingLog } from './parser';

describe('parseSessionRecordingLog', () => {
  it('parses completed AD-like slog and preserves source metadata', () => {
    const text = [
      '{"timestamp":"2026-07-15T16:15:35.140Z","seq":0,"actor":"Administrator","locale":"en-US","host":"IT-HELP-DC","sessionType":"ADConsole","event":"session.start","description":"Session started"}',
      '{"timestamp":"2026-07-15T16:15:41.054Z","seq":1,"event":"session.action","description":"Created User","object":"asdasdasd"}',
      '{"timestamp":"2026-07-15T16:16:32.759Z","seq":2,"event":"session.end","description":"Session ended"}',
      '',
    ].join('\n');

    const result = parseSessionRecordingLog(text);

    expect(result.completionState).toBe('complete');
    expect(result.entries).toHaveLength(3);
    expect(result.entries[0].sourceLineNumber).toBe(1);
    expect(result.entries[1].sourceLineNumber).toBe(2);
    expect(result.entries[0].entry.sessionType).toBe('ADConsole');
  });

  it('marks missing session.end as ended unexpectedly while keeping valid entries', () => {
    const text = [
      '{"timestamp":"2026-07-15T21:17:49.777Z","seq":0,"actor":"Administrator","host":"IT-HELP-DC","sessionType":"ADConsole","event":"session.start","description":"Session started"}',
      '{"timestamp":"2026-07-15T21:19:14.351Z","seq":1,"event":"session.action","description":"Renamed Object","object":"Help Desk Ottawa","parameters":{"New name":"Help Desk Ottawa/Hull"}}',
      '',
    ].join('\n');

    const result = parseSessionRecordingLog(text);

    expect(result.entries).toHaveLength(2);
    expect(result.completionState).toBe('ended-unexpectedly');
    expect(result.warnings.some((warning) => warning.code === 'missing-session-end')).toBe(true);
  });

  it('maps malformed/invalid conditions to canonical warning codes', () => {
    const text = [
      '{"timestamp":"2026-07-16T10:00:00.000Z","seq":0,"event":"session.start","description":"Start","producer":"custom-host"}',
      '{not valid json}',
      '{"timestamp":"2026-07-16T10:00:01.000Z","seq":2,"event":"session.action","description":"Action"}',
      '{"timestamp":"not-a-date","seq":2,"event":"session.unknown","description":"Future event"}',
      '{"timestamp":"2026-07-16T10:00:03.000Z","seq":4,"event":"session.end","description":"End"}',
      '',
    ].join('\n');

    const result = parseSessionRecordingLog(text);

    expect(result.entries).toHaveLength(4);
    expect(result.warnings.some((warning) => warning.code === 'malformed-line')).toBe(true);
    expect(result.warnings.some((warning) => warning.code === 'invalid-field')).toBe(true);
    expect(result.warnings.some((warning) => warning.code === 'duplicate-sequence')).toBe(true);
    expect(result.warnings.some((warning) => warning.code === 'missing-sequence')).toBe(true);
    expect(result.warnings.some((warning) => warning.code === 'unknown-event-type')).toBe(true);
    expect(result.warnings.some((warning) => warning.code === 'sequence-order-mismatch')).toBe(false);
  });

  it('reports unterminated final line as additive informational warning', () => {
    const text = [
      '{"timestamp":"2026-07-16T10:00:00.000Z","seq":0,"event":"session.start","description":"Start"}',
      '{"timestamp":"2026-07-16T10:00:01.000Z","seq":1,"event":"session.end","description":"End"}',
    ].join('\n');

    const result = parseSessionRecordingLog(text);
    expect(result.warnings.some((warning) => warning.code === 'unterminated-final-line')).toBe(true);
  });

  it('applies schema limits using canonical warning categories', () => {
    const deepObject =
      '{"timestamp":"2026-07-16T10:00:00.000Z","seq":0,"event":"session.start","description":"Start","x":{"y":{"z":{"k":1}}}}';
    const hugeLine = `{"timestamp":"2026-07-16T10:00:01.000Z","seq":1,"event":"session.action","description":"${'a'.repeat(600)}"}`;
    const tooManyParameters =
      '{"timestamp":"2026-07-16T10:00:02.000Z","seq":2,"event":"session.action","description":"Action","parameters":{"a":"1","b":"2","c":"3"}}';
    const endLine = '{"timestamp":"2026-07-16T10:00:03.000Z","seq":3,"event":"session.end","description":"End"}';
    const text = [deepObject, hugeLine, tooManyParameters, endLine, ''].join('\n');

    const result = parseSessionRecordingLog(text, {
      maxLineLengthBytes: 2000,
      maxObjectDepth: 3,
      maxParameterCount: 2,
      maxStringLength: 64,
    });

    expect(result.warnings.some((warning) => warning.code === 'entry-limit-exceeded')).toBe(true);
    expect(result.warnings.some((warning) => warning.code === 'invalid-field')).toBe(true);
    expect(result.warnings.some((warning) => warning.code === 'string-truncated')).toBe(true);
    expect(result.entries.some((entry) => entry.entry.event === 'session.end')).toBe(true);
  });

  it('caps missing sequence warnings for very large sequence gaps', () => {
    const text = [
      '{"timestamp":"2026-07-16T10:00:00.000Z","seq":0,"event":"session.start","description":"Start"}',
      '{"timestamp":"2026-07-16T10:00:01.000Z","seq":1000000000,"event":"session.end","description":"End"}',
      '',
    ].join('\n');

    const result = parseSessionRecordingLog(text, {
      maxMissingSequenceWarnings: 3,
    });

    expect(result.entries).toHaveLength(2);
    expect(result.warnings.filter((warning) => warning.code === 'missing-sequence')).toHaveLength(3);
    expect(
      result.warnings.some(
        (warning) =>
          warning.code === 'entry-limit-exceeded' && warning.message.startsWith('missing sequence warnings truncated'),
      ),
    ).toBe(true);
  });

  it('handles deeply nested records without crashing parse flow', () => {
    const depth = 1000;
    let nested = '1';
    for (let index = 0; index < depth; index += 1) {
      nested = `{"k":${nested}}`;
    }

    const text = [
      `{"timestamp":"2026-07-16T10:00:00.000Z","seq":0,"event":"session.start","description":"Start","deep":${nested}}`,
      '{"timestamp":"2026-07-16T10:00:01.000Z","seq":1,"event":"session.end","description":"End"}',
      '',
    ].join('\n');

    const result = parseSessionRecordingLog(text, { maxObjectDepth: 8 });

    expect(result.warnings.some((warning) => warning.code === 'invalid-field')).toBe(true);
    expect(result.entries).toHaveLength(1);
    expect(result.entries[0].entry.event).toBe('session.end');
  });

  it('stops scanning after configured non-empty line limit even when lines are malformed', () => {
    const malformed = Array.from({ length: 20 }, () => '{not valid json}');
    const text = `${malformed.join('\n')}\n`;

    const result = parseSessionRecordingLog(text, { maxScannedLines: 5 });

    expect(result.entries).toHaveLength(0);
    expect(result.warnings.some((warning) => warning.code === 'entry-limit-exceeded')).toBe(true);
  });

  it('treats an empty file as complete and emits no missing-session warnings', () => {
    const result = parseSessionRecordingLog('');

    expect(result.completionState).toBe('complete');
    expect(result.warnings.some((warning) => warning.code === 'missing-session-start')).toBe(false);
    expect(result.warnings.some((warning) => warning.code === 'missing-session-end')).toBe(false);
  });

  it('emits unknown-event-type warning for unrecognized events', () => {
    const text = [
      '{"timestamp":"2026-07-16T10:00:00.000Z","seq":0,"event":"session.start","description":"Start"}',
      '{"timestamp":"2026-07-16T10:00:01.000Z","seq":1,"event":"session.future","description":"Future"}',
      '{"timestamp":"2026-07-16T10:00:02.000Z","seq":2,"event":"session.end","description":"End"}',
      '',
    ].join('\n');

    const result = parseSessionRecordingLog(text);

    expect(result.entries).toHaveLength(3);
    expect(result.warnings.some((warning) => warning.code === 'unknown-event-type')).toBe(true);
  });

  it('caps unknown top-level field collection per record', () => {
    const text = [
      '{"timestamp":"2026-07-16T10:00:00.000Z","seq":0,"event":"session.start","description":"Start","a":1,"b":2,"c":3}',
      '{"timestamp":"2026-07-16T10:00:01.000Z","seq":1,"event":"session.end","description":"End"}',
      '',
    ].join('\n');

    const result = parseSessionRecordingLog(text, { maxUnknownFieldCount: 2 });
    const startEntry = result.entries.find((entry) => entry.entry.event === 'session.start');

    expect(startEntry).toBeDefined();
    expect(Object.keys(startEntry?.entry.unknownFields ?? {})).toHaveLength(2);
    expect(
      result.warnings.some(
        (warning) =>
          warning.code === 'entry-limit-exceeded' &&
          warning.message === 'unknown top-level field count exceeded max limit',
      ),
    ).toBe(true);
  });
});
