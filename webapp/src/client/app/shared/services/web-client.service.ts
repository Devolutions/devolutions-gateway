import {Injectable} from '@angular/core';
import {Observable, of, throwError} from "rxjs";
import {catchError, map, takeUntil} from "rxjs/operators";
import {v4 as uuidv4} from 'uuid';

import {ApiService} from "@shared/services/api.service";
import {UtilsService} from "@shared/services/utils.service";
import {BaseComponent} from "@shared/bases/base.component";
import {WebClientRdpComponent} from "@gateway/modules/web-client/rdp/web-client-rdp.component";
import {ScreenSize} from "@shared/enums/screen-size.enum";
import {DesktopSize} from "@devolutions/iron-remote-gui";
import {WebSession} from "@shared/models/web-session.model";

import {
  IronARDConnectionParameters,
  IronRDPConnectionParameters, IronVNCConnectionParameters,
  sessionTokenParameters,
  SshConnectionParameters,
  TelnetConnectionParameters
} from "@shared/interfaces/connection-params.interfaces";
import {Protocol, WebClientProtocol} from "@shared/enums/web-client-protocol.enum";

export enum DefaultPowerShellPort {
  SSL = 5986,
  NON_SSL = 5985
}

export const DefaultRDPPort: number = 3389;
export const DefaultSshPort: number = 22;
export const DefaultTelnetPort: number = 23;
export const DefaultVncPort: number = 5900;
export const DefaultArdPort: number = 5900;

@Injectable()
export class WebClientService extends BaseComponent {

  constructor( private apiService: ApiService,
               protected utils: UtilsService) {
    super();
  }

  //TODO enhance type safety for form data. KAH Feb 15 2024
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

  fetchToken(tokenParameters: sessionTokenParameters): Observable<string> {
    return this.apiService.generateSessionToken(tokenParameters).pipe(
      takeUntil(this.destroyed$),
      catchError(err => throwError(err))
    );
  }

  fetchProtocolToken(protocol: Protocol, connectionParameters: TelnetConnectionParameters |
                                            SshConnectionParameters |
                                            IronRDPConnectionParameters |
                                            IronVNCConnectionParameters |
                                            IronARDConnectionParameters): Observable<TelnetConnectionParameters |
                                                                                      SshConnectionParameters |
                                                                                      IronRDPConnectionParameters|
                                                                                      IronVNCConnectionParameters|
                                                                                      IronARDConnectionParameters> {
    const protocolStr: string = WebClientProtocol.getEnumKey(protocol).toLowerCase();

    const data: sessionTokenParameters = {
      content_type: "ASSOCIATION",
      protocol: protocolStr,
      destination: `tcp://${connectionParameters.host}:${connectionParameters.port ?? this.getDefaultPort(protocol)}`,
      lifetime: 60,
      session_id: connectionParameters.sessionId || uuidv4(),
    };

    return this.fetchToken(data).pipe(
      takeUntil(this.destroyed$),
      map(token => ({ ...connectionParameters, token })),
      catchError(err => throwError(err))
    );
  }

  private getDefaultPort(protocol: Protocol): number {
    switch(protocol) {
      case Protocol.RDP: return DefaultRDPPort;
      case Protocol.Telnet: return DefaultTelnetPort;
      case Protocol.SSH: return DefaultSshPort;
      case Protocol.VNC: return DefaultVncPort;
      case Protocol.ARD: return DefaultArdPort;
      default: throw new Error(`Getting default port, unsupported protocol: ${protocol}`);
    }
  }

  fetchTelnetToken(connectionParameters: TelnetConnectionParameters): Observable<TelnetConnectionParameters> {
    return this.fetchProtocolToken(Protocol.Telnet, connectionParameters).pipe(
      takeUntil(this.destroyed$),
      map((connectionParameters:TelnetConnectionParameters) => connectionParameters),
      catchError(err => throwError(err))
    );
  }

  fetchSshToken(connectionParameters: SshConnectionParameters): Observable<SshConnectionParameters> {
    return this.fetchProtocolToken(Protocol.SSH, connectionParameters).pipe(
      takeUntil(this.destroyed$),
      map((connectionParameters:SshConnectionParameters) => connectionParameters),
      catchError(err => throwError(err))
    );
  }

  fetchRdpToken(connectionParameters: IronRDPConnectionParameters): Observable<IronRDPConnectionParameters> {
    return this.fetchProtocolToken(Protocol.RDP, connectionParameters).pipe(
      takeUntil(this.destroyed$),
      map((connectionParameters:IronRDPConnectionParameters) => connectionParameters),
      catchError(err => throwError(err))
    );
  }

  fetchVncToken(connectionParameters: IronVNCConnectionParameters): Observable<IronVNCConnectionParameters> {
    return this.fetchProtocolToken(Protocol.VNC, connectionParameters).pipe(
      takeUntil(this.destroyed$),
      map((connectionParameters:IronVNCConnectionParameters) => connectionParameters),
      catchError(err => throwError(err))
    );
  }

  fetchArdToken(connectionParameters: IronARDConnectionParameters): Observable<IronARDConnectionParameters> {
    return this.fetchProtocolToken(Protocol.ARD, connectionParameters).pipe(
      takeUntil(this.destroyed$),
      map((connectionParameters:IronARDConnectionParameters) => connectionParameters),
      catchError(err => throwError(err))
    );
  }

  fetchNetScanToken(): Observable<string> {
    const data: sessionTokenParameters = {
      "content_type": "NETSCAN",
      "lifetime": 60
    };

    return this.fetchToken(data).pipe(
      takeUntil(this.destroyed$),
      catchError(err => throwError(err))
    );
  }

  //TODO refactor kdc token code when I am on the office wifi network KAH Feb 15, 2024
  fetchKdcToken(connectionParameters: IronRDPConnectionParameters): Observable<IronRDPConnectionParameters> {
    if (!connectionParameters.kdcUrl) {
      return of(connectionParameters);
    }

    const data: sessionTokenParameters = {
      "content_type": "KDC",
      "krb_kdc": connectionParameters.kdcUrl,
      "krb_realm": connectionParameters.domain,
      "lifetime": 60
    };

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
