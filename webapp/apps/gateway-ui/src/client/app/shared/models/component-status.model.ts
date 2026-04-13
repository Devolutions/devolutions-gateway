import type { ToastMessageOptions } from 'primeng/api';

export interface ComponentStatus {
  id: string;
  isInitialized: boolean;
  isDisabled?: boolean;
  isDisabledByUser?: boolean;
  /** Error/success message forwarded to the reconnect form when a session ends. */
  terminationMessage?: ToastMessageOptions;
}
