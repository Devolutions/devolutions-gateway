/** Mirrors C# `SessionRecordingKind`. Members name the concept, not the file extension. */
export const SessionRecordingKind = {
  Video: 'video',
  Terminal: 'terminal',
  Log: 'log',
  Unknown: 'unknown',
} as const;

export type SessionRecordingKind = (typeof SessionRecordingKind)[keyof typeof SessionRecordingKind];

/** Mirrors C# `GatewayRecordingManifestFile`. One push segment within a recording. */
export interface GatewayRecordingManifestFile {
  fileName: string;
  startTime?: number;
  duration?: number;
}

/** Mirrors C# `GatewayRecordingManifest`. Only the field this package reads is required. */
export interface GatewayRecordingManifest {
  files: readonly GatewayRecordingManifestFile[];
}

/**
 * Mirrors C# `RecordingArtifact`: one file within a Gateway recording manifest. A recording may
 * contain several artifacts, such as a video plus a session recording log.
 */
export interface RecordingArtifact {
  fileName: string;
  kind: SessionRecordingKind;
  startTime?: number;
  duration?: number;
}

export function isSessionRecordingLogFileName(fileName: string): boolean {
  if (!fileName) {
    return false;
  }

  const lowerCased = fileName.toLowerCase();
  return lowerCased.endsWith('.slog');
}

function getExtension(fileName: string): string {
  const lastDotIndex = fileName.lastIndexOf('.');
  if (lastDotIndex < 0) {
    return '';
  }

  return fileName.slice(lastDotIndex).toLowerCase();
}

export function classifyFileName(fileName: string): SessionRecordingKind {
  if (isSessionRecordingLogFileName(fileName)) {
    return SessionRecordingKind.Log;
  }

  const extension = getExtension(fileName);

  if (extension === '.trp' || extension === '.cast') {
    return SessionRecordingKind.Terminal;
  }

  if (extension === '.webm') {
    return SessionRecordingKind.Video;
  }

  return SessionRecordingKind.Unknown;
}

/**
 * Manifest names are Gateway-generated ASCII, so anything outside this allowlist could redirect or
 * reshape the token-bearing pull URL. Unexpected names are dropped rather than sanitized.
 *
 * Stricter than C#: a bare `.` is rejected because URL resolution removes it as a path segment.
 */
export function isSafeFileName(fileName: string | null | undefined): boolean {
  if (typeof fileName !== 'string' || fileName === '.' || fileName.includes('..')) {
    return false;
  }

  return /^[A-Za-z0-9._-]+$/.test(fileName);
}

/**
 * Mirrors C# `GatewayRecordingManifest.GetArtifacts()`: every manifest file in manifest order, with
 * its kind resolved. Unsafe file names are dropped before classification, as they are in C#.
 */
export function getArtifacts(manifest: GatewayRecordingManifest | null | undefined): RecordingArtifact[] {
  const artifacts: RecordingArtifact[] = [];

  for (const file of manifest?.files ?? []) {
    if (!isSafeFileName(file?.fileName)) {
      continue;
    }

    artifacts.push({
      fileName: file.fileName,
      kind: classifyFileName(file.fileName),
      startTime: file.startTime,
      duration: file.duration,
    });
  }

  return artifacts;
}

/**
 * The viewers a recording can offer: at most one media player and one log viewer. Returned by
 * `getRecordingViewers`.
 */
export interface RecordingViewers {
  media?: { kind: 'video' | 'terminal'; files: GatewayRecordingManifestFile[]; duration: number };
  log?: { files: GatewayRecordingManifestFile[]; duration: number };
  unknownCount: number;
}

/**
 * Groups a manifest into the viewers a recording can offer. Files keep manifest order. Every viewer
 * is returned; choosing one is left to the user, so there is no counterpart to C#
 * `RecordingArtifact.SelectPrimary`.
 *
 * The first media file sets the media kind. Media files of the other kind are counted in
 * `unknownCount`, so every file in the group opens in the same player.
 *
 * A group's `duration` sums its files' durations, skipping any that are missing or not positive.
 */
export function getRecordingViewers(manifest: GatewayRecordingManifest | null | undefined): RecordingViewers {
  let media: RecordingViewers['media'];
  let log: RecordingViewers['log'];
  let unknownCount = 0;

  for (const { kind, ...file } of getArtifacts(manifest)) {
    const fileDuration = file.duration !== undefined && file.duration > 0 ? file.duration : 0;

    if (kind === SessionRecordingKind.Log) {
      log ??= { files: [], duration: 0 };
      log.files.push(file);
      log.duration += fileDuration;
    } else if (kind === SessionRecordingKind.Video || kind === SessionRecordingKind.Terminal) {
      media ??= { kind, files: [], duration: 0 };

      if (media.kind !== kind) {
        unknownCount += 1;
        continue;
      }

      media.files.push(file);
      media.duration += fileDuration;
    } else {
      unknownCount += 1;
    }
  }

  return { media, log, unknownCount };
}
