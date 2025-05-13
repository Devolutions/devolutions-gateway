import { ScreenSize } from '@shared/enums/screen-size.enum';
import { ResolutionQuality } from '../enums/resolution-quality.enum';
import { ArdQualityMode } from '../enums/ard-quality-mode.enum';
import { Encoding } from '../enums/encoding.enum';

export interface HostnameObject {
  hostname: string;
}

export interface AutoCompleteInput {
  hostname: string;
}

export type FormDataUnion =
  | RdpFormDataInput
  | VncFormDataInput
  | ArdFormDataInput
  | SSHFormDataInput
  | TelnetFormDataInput;

export interface RdpFormDataInput {
  autoComplete: AutoCompleteInput;
  hostname: string;
  username: string;
  password: string;
  kdcUrl: string;
  preConnectionBlob: string;
  protocol: number;
  screenSize: ScreenSize;
  customWidth?: number;
  customHeight?: number;
}

export interface VncFormDataInput {
  autoComplete: AutoCompleteInput;
  hostname: string;
  username: string;
  password: string;
  protocol: number;
  disableCursor: boolean;
  enableExtendedClipboard: boolean;
  ultraVirtualDisplay: boolean;
  enabledEncodings: Encoding[];
  screenSize: ScreenSize;
  customWidth?: number;
  customHeight?: number;
}

export interface ArdFormDataInput {
  autoComplete: AutoCompleteInput;
  hostname: string;
  username: string;
  password: string;
  protocol: number;
  resolutionQuality: ResolutionQuality;
  ardQualityMode: ArdQualityMode;
}

export interface TelnetFormDataInput {
  autoComplete: AutoCompleteInput;
  hostname: string;
  username?: string;
  password?: string;
}

export interface SSHFormDataInput {
  autoComplete: AutoCompleteInput;
  hostname: string;
  username?: string;
  password?: string;
  passphrase?: string;
  extraData?: {
    sshPrivateKey?: string;
  };
}
