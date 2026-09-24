export type ServerMessage = ChunkMessage | MetadataMessage | SegmentStartedMessage | ErrorMessage | StreamEndedMessage;

export type StreamCodec = 'vp8' | 'vp9';

export interface ChunkMessage {
  type: 'chunk';
  data: Uint8Array;
}

export interface MetadataMessage {
  type: 'metadata';
  codec: StreamCodec;
}

export interface SegmentStartedMessage {
  type: 'segment-started';
  codec: StreamCodec;
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
    return {
      type: 'metadata',
      codec: parseCodec(buffer),
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

  if (typeCode === 4) {
    return {
      type: 'segment-started',
      codec: parseCodec(buffer),
    };
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

function parseCodec(buffer: ArrayBuffer): StreamCodec {
  const payload = parseJsonPayload(buffer);
  if (payload.codec !== 'vp8' && payload.codec !== 'vp9') {
    throw new Error('Unsupported stream codec');
  }
  return payload.codec;
}
