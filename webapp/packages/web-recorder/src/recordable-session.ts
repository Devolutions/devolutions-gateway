// The minimal contract a session must satisfy to be recorded. The recorder itself only needs to
// know a recording was requested; richer per-app session shapes (DVLS/Hub) structurally satisfy this.
export interface IRecordableSession {
  shouldStartRecording: boolean;
}
