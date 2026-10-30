import { ArdControlMode } from '@shared/interfaces/ard-control.interfaces';

/** Reported by the session through `ardCurtainFailedCallback` when a curtain request did not take effect. */
export type ArdCurtainFailure = 'login-window' | 'lock-screen' | 'not-shown' | 'not-hidden';

/** Reported by the session through `ardControlStateCallback`. */
export interface ArdControlState {
  mode: ArdControlMode;
  availableModes: ArdControlMode[];
  curtainOn: boolean;
  curtainAvailable: boolean;
}

/**
 * The ARD control request in flight.
 *
 * A mode request is settled by the first report showing the requested mode, or showing it unavailable.
 * A curtain request is settled by a `curtainOn` change or a curtain failure, not by the report echoing the request.
 */
export type ArdControlPending = 'mode' | 'show-curtain' | 'hide-curtain';
