import { ColorFormat } from '@shared/enums/color-format.enum';
import { ScreenSize } from '@shared/enums/screen-size.enum';
import { ArdQualityMode } from '../enums/ard-quality-mode.enum';
import { Encoding } from '../enums/encoding.enum';
import { ResolutionQuality } from '../enums/resolution-quality.enum';

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
  enableDisplayControl: boolean;
  kdcUrl: string;
  preConnectionBlob: string;
  protocol: number;
  screenSize: ScreenSize;
  autoClipboard?: boolean;
  customWidth?: number;
  customHeight?: number;
}

export interface VncFormDataInput {
  autoComplete: AutoCompleteInput;
  hostname: string;
  username: string;
  password: string;
  protocol: number;
  enableCursor: boolean;
  // The extended clipboard control may not be initialized if the browser does not support the clipboard API.
  enableExtendedClipboard?: boolean;
  ultraVirtualDisplay: boolean;
  enabledEncoding: Encoding;
  colorFormat: ColorFormat;
  jpegEnabled: boolean;
  jpegQualityLevel: number;
  pngEnabled: boolean;
  wheelSpeedFactor: number;
  screenSize: ScreenSize;
  autoClipboard?: boolean;
  customWidth?: number;
  customHeight?: number;
}

export interface ArdFormDataInput {
  autoComplete: AutoCompleteInput;
  hostname: string;
  username: string;
  password: string;
  protocol: number;
  wheelSpeedFactor: number;
  resolutionQuality: ResolutionQuality;
  ardQualityMode: ArdQualityMode;
  autoClipboard?: boolean;
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
