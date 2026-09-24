import { describe, expect, it } from 'vitest';
import { parseServerMessage } from './protocol';

function encodedMessage(type: number, payload = ''): ArrayBuffer {
  const encodedPayload = new TextEncoder().encode(payload);
  const message = new Uint8Array(1 + encodedPayload.length);
  message[0] = type;
  message.set(encodedPayload, 1);
  return message.buffer;
}

describe('parseServerMessage', () => {
  it('accepts legacy one-segment metadata', () => {
    expect(parseServerMessage(encodedMessage(1, '{"codec":"vp9"}'))).toEqual({
      type: 'metadata',
      codec: 'vp9',
    });
  });

  it('parses a later segment boundary', () => {
    expect(parseServerMessage(encodedMessage(4, '{"codec":"vp8"}'))).toEqual({
      type: 'segment-started',
      codec: 'vp8',
    });
  });

  it('requires stream-ended to have no payload', () => {
    expect(parseServerMessage(encodedMessage(3))).toEqual({ type: 'stream-ended' });
    expect(() => parseServerMessage(encodedMessage(3, 'unexpected'))).toThrow('Invalid stream-ended message');
  });

  it('rejects an unsupported segment codec', () => {
    expect(() => parseServerMessage(encodedMessage(4, '{"codec":"av1"}'))).toThrow('Unsupported stream codec');
  });
});
