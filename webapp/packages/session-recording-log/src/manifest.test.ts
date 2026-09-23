import { describe, expect, it } from 'vitest';
import {
  classifyFileName,
  type GatewayRecordingManifest,
  getArtifacts,
  getRecordingViewers,
  isSafeFileName,
  SessionRecordingKind,
} from './manifest';

// Mirrors RecordingArtifactTests.cs. The SelectPrimary and BuildSiblingUri cases are deliberately
// absent: this package keeps every artifact instead of picking one, and builds no URIs.

const unsafeFileNames = [
  '../recording-0.slog',
  'sub/recording-0.slog',
  'sub\\recording-0.slog',
  '',
  'recording?token=x.slog',
  'recording#frag.slog',
  'recording%2e%2e.slog',
  'recording:0.slog',
  'recording 0.slog',
];

describe('classifyFileName', () => {
  const cases: [string, SessionRecordingKind][] = [
    ['recording-0.slog', SessionRecordingKind.Log],
    ['recording-0.SLOG', SessionRecordingKind.Log],
    ['recording-0.trp', SessionRecordingKind.Terminal],
    ['recording-0.cast', SessionRecordingKind.Terminal],
    ['recording-0.webm', SessionRecordingKind.Video],
    ['recording-0.bin', SessionRecordingKind.Unknown],
  ];

  it.each(cases)('maps %s to %s', (fileName, expected) => {
    expect(classifyFileName(fileName)).toBe(expected);
  });

  it('treats a name without an extension as unknown', () => {
    expect(classifyFileName('recording')).toBe(SessionRecordingKind.Unknown);
  });
});

describe('isSafeFileName', () => {
  it.each(unsafeFileNames)('rejects %j', (fileName) => {
    expect(isSafeFileName(fileName)).toBe(false);
  });

  it('rejects null and undefined', () => {
    expect(isSafeFileName(null)).toBe(false);
    expect(isSafeFileName(undefined)).toBe(false);
  });

  it('accepts Gateway-generated names', () => {
    expect(isSafeFileName('recording-0.webm')).toBe(true);
    expect(isSafeFileName('recording-12.slog')).toBe(true);
    expect(isSafeFileName('recording_0.cast')).toBe(true);
  });
});

describe('getArtifacts', () => {
  it('reads the Gateway manifest shape', () => {
    const manifest = JSON.parse(`{
      "sessionId": "0c3f24a1-49a5-46e3-8ba0-a97dd9d7dc12",
      "startTime": 1752614269,
      "duration": 131,
      "files": [
        { "fileName": "recording-0.webm", "startTime": 1752614269, "duration": 131 },
        { "fileName": "recording-0.slog", "startTime": 1752614269, "duration": 131 }
      ]
    }`) as GatewayRecordingManifest;

    const artifacts = getArtifacts(manifest);

    expect(artifacts).toHaveLength(2);
    expect(artifacts[0]?.kind).toBe(SessionRecordingKind.Video);
    expect(artifacts[1]?.kind).toBe(SessionRecordingKind.Log);
    expect(artifacts[1]?.duration).toBe(131);
  });

  it.each(unsafeFileNames)('drops %j', (fileName) => {
    expect(getArtifacts({ files: [{ fileName }] })).toEqual([]);
  });

  it('preserves manifest order', () => {
    const artifacts = getArtifacts({
      files: [
        { fileName: 'recording-0.webm' },
        { fileName: 'recording-1.slog' },
        { fileName: 'recording-2.webm' },
        { fileName: 'recording-3.bin' },
      ],
    });

    expect(artifacts.map((artifact) => artifact.fileName)).toEqual([
      'recording-0.webm',
      'recording-1.slog',
      'recording-2.webm',
      'recording-3.bin',
    ]);
    expect(artifacts.map((artifact) => artifact.kind)).toEqual([
      SessionRecordingKind.Video,
      SessionRecordingKind.Log,
      SessionRecordingKind.Video,
      SessionRecordingKind.Unknown,
    ]);
  });

  it('keeps unknown artifacts rather than dropping them', () => {
    const artifacts = getArtifacts({ files: [{ fileName: 'recording-0.bin' }] });

    expect(artifacts).toHaveLength(1);
    expect(artifacts[0]?.kind).toBe(SessionRecordingKind.Unknown);
  });

  it('returns an empty list for a missing or empty manifest', () => {
    expect(getArtifacts(undefined)).toEqual([]);
    expect(getArtifacts(null)).toEqual([]);
    expect(getArtifacts({ files: [] })).toEqual([]);
  });
});

describe('getRecordingViewers', () => {
  it('offers two viewers, not six, for five video clips and one log', () => {
    const viewers = getRecordingViewers({
      files: [
        { fileName: 'recording-0.webm', duration: 10 },
        { fileName: 'recording-1.webm', duration: 20 },
        { fileName: 'recording-2.webm', duration: 30 },
        { fileName: 'recording-3.webm', duration: 40 },
        { fileName: 'recording-4.webm', duration: 50 },
        { fileName: 'recording-0.slog', duration: 150 },
      ],
    });

    expect(viewers.media?.kind).toBe(SessionRecordingKind.Video);
    expect(viewers.media?.files.map((file) => file.fileName)).toEqual([
      'recording-0.webm',
      'recording-1.webm',
      'recording-2.webm',
      'recording-3.webm',
      'recording-4.webm',
    ]);
    expect(viewers.media?.duration).toBe(150);
    expect(viewers.log?.files.map((file) => file.fileName)).toEqual(['recording-0.slog']);
    expect(viewers.log?.duration).toBe(150);
    expect(viewers.unknownCount).toBe(0);
  });

  it('returns files without their kind', () => {
    const viewers = getRecordingViewers({ files: [{ fileName: 'recording-0.cast', startTime: 5, duration: 7 }] });

    expect(viewers.media).toEqual({
      kind: SessionRecordingKind.Terminal,
      files: [{ fileName: 'recording-0.cast', startTime: 5, duration: 7 }],
      duration: 7,
    });
  });

  it('offers only a log viewer for a log-only recording', () => {
    const viewers = getRecordingViewers({ files: [{ fileName: 'recording-0.slog' }] });

    expect(viewers.media).toBeUndefined();
    expect(viewers.log?.files).toHaveLength(1);
  });

  it('groups several log files into one log viewer and sums their durations', () => {
    const viewers = getRecordingViewers({
      files: [
        { fileName: 'recording-0.slog', duration: 40 },
        { fileName: 'recording-1.webm', duration: 90 },
        { fileName: 'recording-2.slog', duration: 50 },
      ],
    });

    expect(viewers.log?.files.map((file) => file.fileName)).toEqual(['recording-0.slog', 'recording-2.slog']);
    expect(viewers.log?.duration).toBe(90);
  });

  it('lets the first media file set the kind and counts the other kind as unknown', () => {
    const viewers = getRecordingViewers({
      files: [{ fileName: 'recording-0.webm' }, { fileName: 'recording-1.cast' }, { fileName: 'recording-2.webm' }],
    });

    expect(viewers.media?.kind).toBe(SessionRecordingKind.Video);
    expect(viewers.media?.files.map((file) => file.fileName)).toEqual(['recording-0.webm', 'recording-2.webm']);
    expect(viewers.unknownCount).toBe(1);
  });

  it('counts unknown files without returning them', () => {
    const viewers = getRecordingViewers({
      files: [{ fileName: 'recording-0.bin' }, { fileName: 'recording-1.webm' }, { fileName: 'notes.txt' }],
    });

    expect(viewers.media?.files).toHaveLength(1);
    expect(viewers.log).toBeUndefined();
    expect(viewers.unknownCount).toBe(2);
  });

  it('drops unsafe file names without counting them', () => {
    const viewers = getRecordingViewers({
      files: [{ fileName: '../recording-0.slog' }, { fileName: 'recording-1.slog' }],
    });

    expect(viewers.log?.files.map((file) => file.fileName)).toEqual(['recording-1.slog']);
    expect(viewers.unknownCount).toBe(0);
  });

  it('skips missing, zero, negative, and NaN durations when summing', () => {
    const viewers = getRecordingViewers({
      files: [
        { fileName: 'recording-0.webm', duration: 12 },
        { fileName: 'recording-1.webm' },
        { fileName: 'recording-2.webm', duration: 0 },
        { fileName: 'recording-3.webm', duration: -4 },
        { fileName: 'recording-4.webm', duration: Number.NaN },
        { fileName: 'recording-5.webm', duration: 3 },
      ],
    });

    expect(viewers.media?.files).toHaveLength(6);
    expect(viewers.media?.duration).toBe(15);
  });

  it('offers no viewers for a missing or empty manifest', () => {
    for (const manifest of [undefined, null, { files: [] }]) {
      const viewers = getRecordingViewers(manifest);

      expect(viewers.media).toBeUndefined();
      expect(viewers.log).toBeUndefined();
      expect(viewers.unknownCount).toBe(0);
    }
  });
});
