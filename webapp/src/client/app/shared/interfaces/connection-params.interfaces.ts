import {DesktopSize} from "@devolutions/iron-remote-gui";

export interface sessionTokenParameters {
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
  gatewayAddress?: string;
  token?: string;
  kdcToken?: string
  screenSize?: DesktopSize;
  kdcUrl?: string;
  kdcProxyUrl?: string;
  preConnectionBlob?:string
  sessionId?: string
}

export interface IronVNCConnectionParameters {
  host: string;
  username?: string;
  password: string;
  domain?: string;
  port?: number;
  gatewayAddress?: string;
  token?: string;
  kdcToken?: string
  screenSize?: DesktopSize;
  kdcUrl?: string;
  kdcProxyUrl?: string;
  preConnectionBlob?:string
  sessionId?: string
}

export interface IronARDConnectionParameters {
  host: string;
  username: string;
  password: string;
  domain?: string;
  port?: number;
  gatewayAddress?: string;
  token?: string;
  kdcToken?: string
  screenSize?: DesktopSize;
  kdcUrl?: string;
  kdcProxyUrl?: string;
  preConnectionBlob?:string
  sessionId?: string
}

export interface TelnetConnectionParameters {
  host: string;
  port: number;
  gatewayAddress?: string;
  token?: string;
  sessionId?: string
}

export interface SshConnectionParameters {
  host: string;
  port: number;
  username?: string;
  password?: string;
  gatewayAddress?: string;
  token?: string;
  sessionId?: string
}
