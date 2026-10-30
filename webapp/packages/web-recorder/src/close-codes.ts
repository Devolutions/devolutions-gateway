/**
 * WebSocket close code a recorder sends when the user stops the recording.
 *
 * Devolutions Gateway then ends the recording at once, so live viewers see the end right away.
 * Any other close keeps the recording open until its reconnection window passes.
 */
export const RECORDING_ENDED_CLOSE_CODE = 4011;
