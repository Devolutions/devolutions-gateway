export type ServerMessage = ChunkMessage | SegmentStartedMessage | ErrorMessage | StreamEndedMessage;

export interface ChunkMessage {
  type: 'chunk';
  data: Uint8Array;
}

export interface SegmentStartedMessage {
  type: 'segment-started';
  codec: 'vp8' | 'vp9';
  sequence: number;
  width?: number;
  height?: number;
}

export interface ErrorMessage {
  type: 'error';
  error: 'UnexpectedError';
}

export interface StreamEndedMessage {
  type: 'stream-ended';
}

export interface ClientMessage {
  type: 'start' | 'pull';
}

export function parseServerMessage(buffer: ArrayBuffer): ServerMessage {
  if (buffer.byteLength === 0) {
    throw new Error('Empty server message');
  }

  const typeCode = new DataView(buffer).getUint8(0);
  if (typeCode === 0) {
    return {
      type: 'chunk',
      data: new Uint8Array(buffer, 1),
    };
  }

  if (typeCode === 1) {
    const metadata = parseJsonPayload(buffer);
    if (metadata.sequence === undefined && metadata.width === undefined && metadata.height === undefined) {
      if (metadata.codec !== 'vp8' && metadata.codec !== 'vp9') {
        throw new Error('Unsupported stream codec');
      }
      return {
        type: 'segment-started',
        codec: metadata.codec,
        sequence: 0,
      };
    }

    if (metadata.codec !== 'vp8') {
      throw new Error('Unsupported stream codec');
    }

    return {
      type: 'segment-started',
      codec: metadata.codec,
      sequence: readInteger(metadata.sequence, 'sequence', 0),
      width: readInteger(metadata.width, 'width', 1),
      height: readInteger(metadata.height, 'height', 1),
    };
  }

  if (typeCode === 2) {
    const payload = parseJsonPayload(buffer);
    if (payload.error !== 'UnexpectedError') {
      throw new Error('Unknown server error');
    }
    return {
      type: 'error',
      error: payload.error,
    };
  }

  if (typeCode === 3) {
    if (buffer.byteLength !== 1) {
      throw new Error('Invalid stream-ended message');
    }
    return { type: 'stream-ended' };
  }

  throw new Error('Unknown server message type');
}

export function parseClientMessage(message: ClientMessage): Uint8Array {
  if (message.type === 'start') {
    return new Uint8Array([0]);
  }
  return new Uint8Array([1]);
}

function parseJsonPayload(buffer: ArrayBuffer): Record<string, unknown> {
  const text = new TextDecoder('utf-8', { fatal: true }).decode(new Uint8Array(buffer, 1));
  const value: unknown = JSON.parse(text);
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new Error('Invalid server message payload');
  }
  return value as Record<string, unknown>;
}

function readInteger(value: unknown, field: string, minimum: number): number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < minimum) {
    throw new Error(`Invalid ${field}`);
  }
  return value;
}
