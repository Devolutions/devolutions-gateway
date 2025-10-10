import { LoadingMode } from '../enums/loading-mode.enum';

export interface LoadingEvent {
  isLoading: boolean;
  receiver: unknown;
  mode: LoadingMode;
}
