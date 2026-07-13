import { DesktopSize } from '@shared/models/desktop-size';

export interface SessionTokenParameters {
  content_type: string;
  protocol?: string;
  destination?: string;
  lifetime: number;
  session_id?: string;
  krb_kdc?: string;
  krb_realm?: string;
}

export interface IronRDPConnectionParameters {
  host: string;
  username: string;
  password: string;
  domain?: string;
  port?: number;
  gatewayAddress: string;
  token?: string;
  kdcToken?: string;
  screenSize?: DesktopSize;
  enableDisplayControl: boolean;
  kdcUrl?: string;
  kdcProxyUrl?: string;
  preConnectionBlob?: string;
  sessionId?: string;
}

export interface IronVNCConnectionParameters {
  host: string;
  username?: string;
  password: string;
  port?: number;
  gatewayAddress?: string;
  token?: string;
  screenSize?: DesktopSize;
  enabledEncodings?: string;
  colorFormat: string;
  jpegQualityLevel?: number;
  enableCursor: boolean;
  enableExtendedClipboard: boolean;
  ultraVirtualDisplay: boolean;
  wheelSpeedFactor: number;
  sessionId?: string;
}

export interface IronARDConnectionParameters {
  host: string;
  username: string;
  password: string;
  port?: number;
  gatewayAddress?: string;
  token?: string;
  resolutionQuality?: string;
  ardQualityMode?: string;
  wheelSpeedFactor: number;
  sessionId?: string;
}

export interface TelnetConnectionParameters {
  host: string;
  port: number;
  gatewayAddress?: string;
  token?: string;
  sessionId?: string;
}

export interface SshConnectionParameters {
  host: string;
  port: number;
  username?: string;
  password?: string;
  gatewayAddress?: string;
  token?: string;
  sessionId?: string;
  privateKey?: string;
  privateKeyPassphrase?: string;
}

export interface ActiveDirectoryConnectionParameters {
  host: string;
  port: number;
  username: string;
  password: string;
  domain?: string;
  gatewayAddress: string;
  token?: string;
  kdcUrl?: string;
  sessionId?: string;
  useLdaps: boolean;
  organizationalUnit?: string;
}

export function isActiveDirectoryConnectionParameters(params: unknown): params is ActiveDirectoryConnectionParameters {
  if (typeof params !== 'object' || params === null) {
    return false;
  }

  const candidate = params as Partial<ActiveDirectoryConnectionParameters>;

  return (
    typeof candidate.host === 'string' &&
    typeof candidate.port === 'number' &&
    Number.isInteger(candidate.port) &&
    candidate.port >= 1 &&
    candidate.port <= 65535 &&
    typeof candidate.username === 'string' &&
    typeof candidate.password === 'string' &&
    typeof candidate.gatewayAddress === 'string' &&
    typeof candidate.useLdaps === 'boolean'
  );
}
