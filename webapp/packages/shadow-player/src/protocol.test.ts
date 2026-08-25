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
      type: 'segment-started',
      codec: 'vp9',
      sequence: 0,
    });
  });

  it('parses independent segment metadata', () => {
    expect(parseServerMessage(encodedMessage(1, '{"codec":"vp8","sequence":2,"width":1280,"height":720}'))).toEqual({
      type: 'segment-started',
      codec: 'vp8',
      sequence: 2,
      width: 1280,
      height: 720,
    });
  });

  it('requires stream-ended to have no payload', () => {
    expect(parseServerMessage(encodedMessage(3))).toEqual({ type: 'stream-ended' });
    expect(() => parseServerMessage(encodedMessage(3, 'unexpected'))).toThrow('Invalid stream-ended message');
  });

  it('rejects partially extended metadata', () => {
    expect(() => parseServerMessage(encodedMessage(1, '{"codec":"vp8","sequence":0}'))).toThrow('Invalid width');
  });
});
