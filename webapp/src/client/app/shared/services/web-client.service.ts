import {Injectable} from '@angular/core';

export enum DefaultPowerShellPort {
  SSL = 5986,
  NON_SSL = 5985
}

export const DefaultRDPPort: number = 3389;
export const DefaultSshPort: number = 22;
export const DefaultTelnetPort: number = 23;
// export const SessionConnectionTypes = [
//   ConnectionType.SSHShell,
//   ConnectionType.RDPConfigured,
//   ConnectionType.PowerShellRemoteConsole,
//   ConnectionType.Telnet
// ];

export interface WebClientQueryParams {
  sessionId: string;
  gatewayUrl: URL;
  gatewayToken: string;
  comment?: string;
  ticketNumber?: string;
}

export interface WebClientCredentials {
  queryParams?: WebClientQueryParams;
  token?: string;
  host?: string;
  port?: number;
  username?: string;
  safePassword?: string;
  password?: string;
  domain?: string;
  url?: string;
  useSSL?: boolean;
  isConnected?: boolean;
  hasError?: boolean;
}

export interface IronRDPConnectionParameters {
  host: string;
  username: string;
  password: string;
  domain?: string;
  gatewayAddress?: string;
  token?: string;
  screenSize?: { width: number, height: number };
  kdcProxyUrl?: string;
  preConnectionBlob?:string
}

@Injectable()
export class WebClientService {

  constructor() {
  }

  //TODO getWebClientQueryString

  //TODO buildWebClientQueryParams
  //TODO getConnectionGatewayToken

  //TODO generateGatewayToken

  //TODO isGatewayReachable
}
