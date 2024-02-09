import {Injectable} from '@angular/core';
import {Observable, of, throwError} from "rxjs";
import {catchError, map, takeUntil} from "rxjs/operators";
import { v4 as uuidv4 } from 'uuid';

import {ApiService} from "@shared/services/api.service";
import {UtilsService} from "@shared/services/utils.service";
import {BaseComponent} from "@shared/bases/base.component";
import {WebClientRdpComponent} from "@gateway/modules/web-client/rdp/web-client-rdp.component";
import {ScreenSize} from "@shared/enums/screen-size.enum";
import {DesktopSize} from "@devolutions/iron-remote-gui";
import {WebSession} from "@shared/models/web-session.model";
import {SelectItem} from "primeng/api";

export enum DefaultPowerShellPort {
  SSL = 5986,
  NON_SSL = 5985
}

export const PROTOCOL_SELECT_ITEMS: SelectItem[] = [
  { label: 'RDP', value: '0' }
];

export const DefaultRDPPort: number = 3389;
export const DefaultSshPort: number = 22;
export const DefaultTelnetPort: number = 23;
// export const SessionConnectionTypes = [
//   ConnectionType.SSHShell,
//   ConnectionType.RDPConfigured,
//   ConnectionType.PowerShellRemoteConsole,
//   ConnectionType.Telnet
// ];

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

export interface HostnameObject {
  hostname: string;
}

export interface AutoCompleteInput {
  hostname: string;
}

export interface RdpFormDataInput {
  autoComplete: AutoCompleteInput,
  hostname: string,
  username: string,
  password: string,
  kdcUrl: string,
  preConnectionBlob: string,
  protocol: number,
  screenSize: ScreenSize,
  customWidth?: number,
  customHeight?: number
}

@Injectable()
export class WebClientService extends BaseComponent {

  constructor( private apiService: ApiService,
               protected utils: UtilsService) {
    super();
  }

  getDesktopSize(submittedFormData: any ): DesktopSize | null {
    if (!submittedFormData?.screenSize) {
      return;
    }

    const screenSizeStr: string = ScreenSize.getEnumKey(submittedFormData.screenSize);
    if (submittedFormData.screenSize >= 2 && submittedFormData.screenSize <= 20) {
      const rawSize: string[] = screenSizeStr?.split('x');
      return rawSize.length > 1 ? { width: parseInt(rawSize[0]), height: (parseInt(rawSize[1])-WebSession.TOOLBAR_SIZE) } : null;

    } else if (submittedFormData.screenSize === ScreenSize.Custom) {
      return submittedFormData.customWidth && submittedFormData.customHeight ?
        { width: submittedFormData.customWidth, height: (submittedFormData.customHeight-WebSession.TOOLBAR_SIZE) } :
        null;
    }
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
