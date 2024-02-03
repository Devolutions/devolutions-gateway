import {Injectable} from '@angular/core';
import {Observable, of, throwError} from "rxjs";
import {catchError, map, takeUntil} from "rxjs/operators";
import { v4 as uuidv4 } from 'uuid';

import { ApiService } from "@shared/services/api.service";
import {UtilsService} from "@shared/services/utils.service";
import {BaseComponent} from "@shared/bases/base.component";
import {WebClientRdpComponent} from "@gateway/modules/web-client/rdp/web-client-rdp.component";

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
  kdcToken?: string
  screenSize?: DesktopSize;
  kdcUrl?: string;
  kdcProxyUrl?: string;
  preConnectionBlob?:string
}

export interface DesktopSize {
  width: number;
  height: number;
}

@Injectable()
export class WebClientService extends BaseComponent {

  static JET_RDP_URL: string = '/jet/rdp';
  static JET_KDC_PROXY_URL: string = '/jet/KdcProxy';

  constructor( private apiService: ApiService,
               protected utils: UtilsService) {
    super();
  }

  fetchToken(sessionParameters: any): Observable<string> {
    return this.apiService.generateSessionToken(sessionParameters).pipe(
      takeUntil(this.destroyed$),
      catchError(err => throwError(err))
    );
  }

  fetchRdpToken(connectionParameters: IronRDPConnectionParameters): Observable<IronRDPConnectionParameters> {
    const data = {
      "content_type": "ASSOCIATION",
      "protocol": "rdp",
      "destination": `tcp://${connectionParameters.host}:${DefaultRDPPort}`,
      "lifetime": 60,
      "session_id": uuidv4()
    }

    return this.fetchToken(data).pipe(
      takeUntil(this.destroyed$),
      map((token: string): IronRDPConnectionParameters => ({
        ...connectionParameters,
        token: token
      })),
      catchError(err => throwError(err))
    );
  }

  fetchKdcToken(connectionParameters: IronRDPConnectionParameters): Observable<IronRDPConnectionParameters> {
    if (!connectionParameters.kdcUrl) {
      return of(connectionParameters);
    }

    const data = {
      "content_type": "KDC",
      "krb_kdc": connectionParameters.kdcUrl,
      "krb_realm": connectionParameters.domain,
      "lifetime": 60
    }

    return this.fetchToken(data).pipe(
      takeUntil(this.destroyed$),
      map((token: string): IronRDPConnectionParameters => ({
        ...connectionParameters,
        kdcToken: token
      })),
      catchError(err => throwError(err))
    );
  }

  generateKdcProxyUrl(connectionParameters: IronRDPConnectionParameters): Observable<IronRDPConnectionParameters> {
    if (!connectionParameters.kdcToken) {
      return of(connectionParameters);
    }

    const currentURL: URL = new URL(WebClientRdpComponent.JET_KDC_PROXY_URL, window.location.href);
    connectionParameters.kdcProxyUrl = `${currentURL.href}/${connectionParameters.kdcToken}`;
    return of(connectionParameters);
  }
}
