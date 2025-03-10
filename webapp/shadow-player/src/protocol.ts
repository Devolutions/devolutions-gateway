// Define the message types
export type ServerMessage = ChunkMessage | MetaDataMessage | ErrorMessage | EndMessage;

export interface ChunkMessage {
  type: 'chunk';
  data: Uint8Array;
}

export interface ErrorMessage {
  type: 'error';
  error: 'UnexpectedError' | 'UnexpectedEOF';
}

export interface MetaDataMessage {
  type: 'metadata';
  codec: 'vp8' | 'vp9';
}

export interface EndMessage {
  type: 'end';
}

export type ClientMessageTypes = 'start' | 'pull';

export interface ClientMessage {
  type: ClientMessageTypes;
}

// Function to parse the message
export function parseServerMessage(buffer: ArrayBuffer): ServerMessage {
  const view = new DataView(buffer);
  const typeCode = view.getUint8(0); // Read the first byte as the type code

  if (typeCode === 0) {
    // Chunk message
    const chunkData = new Uint8Array(buffer, 1); // The rest is the chunk data
    return {
      type: 'chunk',
      data: chunkData,
    };
  }
  if (typeCode === 1) {
    // Metadata message (JSON)
    const jsonString = new TextDecoder().decode(new Uint8Array(buffer, 1)); // Decode the rest as a string
    const json = JSON.parse(jsonString);

    return {
      type: 'metadata',
      codec: json.codec === 'vp8' ? 'vp8' : 'vp9',
    };
  }

  if (typeCode === 2) {
    // Metadata message (JSON)
    const jsonString = new TextDecoder().decode(new Uint8Array(buffer, 1)); // Decode the rest as a string
    const json = JSON.parse(jsonString);

    return {
      type: 'error',
      error: json.error,
    };
  }

  if (typeCode === 3) {
    return {
      type: 'end',
    };
  }

  throw new Error('Unknown message type');
}

export function parseClientMessage(message: ClientMessage): Uint8Array {
  if (message.type === 'start') {
    return new Uint8Array([0]);
  }
  if (message.type === 'pull') {
    return new Uint8Array([1]);
  }
  throw new Error('Unknown message type');
}
