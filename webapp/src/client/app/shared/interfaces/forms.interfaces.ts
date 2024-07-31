import { ScreenSize } from '@shared/enums/screen-size.enum';

export interface HostnameObject {
  hostname: string;
}

export interface AutoCompleteInput {
  hostname: string;
}

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
  kdcUrl: string;
  preConnectionBlob: string;
  protocol: number;
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
  screenSize: ScreenSize;
  customWidth?: number;
  customHeight?: number;
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
