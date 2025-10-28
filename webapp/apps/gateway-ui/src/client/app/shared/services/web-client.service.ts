import { Injectable } from '@angular/core';
import { JET_KDC_PROXY_URL } from '@gateway/app.constants';
import { BaseComponent } from '@shared/bases/base.component';
import { ScreenSize } from '@shared/enums/screen-size.enum';
import { Protocol, WebClientProtocol } from '@shared/enums/web-client-protocol.enum';
import {
  IronARDConnectionParameters,
  IronRDPConnectionParameters,
  IronVNCConnectionParameters,
  SessionTokenParameters,
  SshConnectionParameters,
  TelnetConnectionParameters,
} from '@shared/interfaces/connection-params.interfaces';
import { DesktopSize } from '@shared/models/desktop-size';
import { ApiService } from '@shared/services/api.service';
import { UtilsService } from '@shared/services/utils.service';
import { Observable, of, throwError } from 'rxjs';
import { catchError, map, takeUntil } from 'rxjs/operators';
import { v4 as uuidv4 } from 'uuid';

export enum DefaultPowerShellPort {
  SSL = 5986,
  NON_SSL = 5985,
}

export const DefaultRDPPort: number = 3389;
export const DefaultSshPort: number = 22;
export const DefaultTelnetPort: number = 23;
export const DefaultVncPort: number = 5900;
export const DefaultArdPort: number = 5900;

@Injectable()
export class WebClientService extends BaseComponent {
  constructor(
    private apiService: ApiService,
    protected utils: UtilsService,
  ) {
    super();
  }

  //TODO enhance type safety for form data. KAH Feb 15 2024
  getDesktopSize(submittedFormData): DesktopSize | null {
    if (!submittedFormData?.screenSize) {
      return;
    }

    const screenSizeStr: string = ScreenSize.getEnumKey(submittedFormData.screenSize);
    if (submittedFormData.screenSize >= 2 && submittedFormData.screenSize <= 20) {
      const rawSize: string[] = screenSizeStr?.split('x');
      return rawSize.length > 1 ? { width: Number.parseInt(rawSize[0]), height: Number.parseInt(rawSize[1]) } : null;
    }
    if (submittedFormData.screenSize === ScreenSize.Custom) {
      return submittedFormData.customWidth && submittedFormData.customHeight
        ? { width: submittedFormData.customWidth, height: submittedFormData.customHeight }
        : null;
    }
  }

  fetchToken(tokenParameters: SessionTokenParameters): Observable<string> {
    return this.apiService.generateSessionToken(tokenParameters).pipe(
      takeUntil(this.destroyed$),
      catchError((err) => throwError(err)),
    );
  }

  private getDefaultPort(protocol: Protocol): number {
    switch (protocol) {
      case Protocol.RDP:
        return DefaultRDPPort;
      case Protocol.Telnet:
        return DefaultTelnetPort;
      case Protocol.SSH:
        return DefaultSshPort;
      case Protocol.VNC:
        return DefaultVncPort;
      case Protocol.ARD:
        return DefaultArdPort;
      default:
        throw new Error(`Getting default port, unsupported protocol: ${protocol}`);
    }
  }

  private handleProtocolTokenRequest<
    T extends
      | TelnetConnectionParameters
      | SshConnectionParameters
      | IronRDPConnectionParameters
      | IronVNCConnectionParameters
      | IronARDConnectionParameters,
  >(protocol: Protocol, connectionParameters: T): Observable<T> {
    return this.generateProtocolToken(protocol, connectionParameters).pipe(
      takeUntil(this.destroyed$),
      map((params) => params as T),
      catchError((err) => throwError(() => err)),
    );
  }

  generateProtocolToken(
    protocol: Protocol,
    connectionParameters:
      | TelnetConnectionParameters
      | SshConnectionParameters
      | IronRDPConnectionParameters
      | IronVNCConnectionParameters
      | IronARDConnectionParameters,
  ): Observable<
    | TelnetConnectionParameters
    | SshConnectionParameters
    | IronRDPConnectionParameters
    | IronVNCConnectionParameters
    | IronARDConnectionParameters
  > {
    const protocolStr: string = WebClientProtocol.getEnumKey(protocol).toLowerCase();

    const data: SessionTokenParameters = {
      content_type: 'ASSOCIATION',
      protocol: protocolStr,
      destination: `tcp://${connectionParameters.host}:${connectionParameters.port ?? this.getDefaultPort(protocol)}`,
      lifetime: 60,
      session_id: connectionParameters.sessionId || uuidv4(),
    };

    return this.fetchToken(data).pipe(
      takeUntil(this.destroyed$),
      map((token) => {
        return { ...connectionParameters, token } as typeof connectionParameters;
      }),
      catchError((_err) => {
        return throwError(() => new Error('Failed to fetch protocol token'));
      }),
    );
  }

  fetchTelnetToken(connectionParameters: TelnetConnectionParameters): Observable<TelnetConnectionParameters> {
    return this.handleProtocolTokenRequest(Protocol.Telnet, connectionParameters);
  }

  fetchSshToken(connectionParameters: SshConnectionParameters): Observable<SshConnectionParameters> {
    return this.handleProtocolTokenRequest(Protocol.SSH, connectionParameters);
  }

  fetchRdpToken(connectionParameters: IronRDPConnectionParameters): Observable<IronRDPConnectionParameters> {
    return this.handleProtocolTokenRequest(Protocol.RDP, connectionParameters);
  }

  fetchVncToken(connectionParameters: IronVNCConnectionParameters): Observable<IronVNCConnectionParameters> {
    return this.handleProtocolTokenRequest(Protocol.VNC, connectionParameters);
  }

  fetchArdToken(connectionParameters: IronARDConnectionParameters): Observable<IronARDConnectionParameters> {
    return this.handleProtocolTokenRequest(Protocol.ARD, connectionParameters);
  }

  fetchNetScanToken(): Observable<string> {
    const data: SessionTokenParameters = {
      content_type: 'NETSCAN',
      lifetime: 60,
    };

    return this.fetchToken(data).pipe(
      takeUntil(this.destroyed$),
      catchError((err) => throwError(err)),
    );
  }

  //TODO refactor kdc token code when I am on the office wifi network KAH Feb 15, 2024
  fetchKdcToken(connectionParameters: IronRDPConnectionParameters): Observable<IronRDPConnectionParameters> {
    if (!connectionParameters.kdcUrl) {
      return of(connectionParameters);
    }

    const data: SessionTokenParameters = {
      content_type: 'KDC',
      krb_kdc: connectionParameters.kdcUrl,
      krb_realm: connectionParameters.domain,
      lifetime: 60,
    };

    return this.fetchToken(data).pipe(
      takeUntil(this.destroyed$),
      map(
        (token: string): IronRDPConnectionParameters => ({
          ...connectionParameters,
          kdcToken: token,
        }),
      ),
      catchError((err) => throwError(err)),
    );
  }

  generateKdcProxyUrl(connectionParameters: IronRDPConnectionParameters): Observable<IronRDPConnectionParameters> {
    if (!connectionParameters.kdcToken) {
      return of(connectionParameters);
    }

    const currentURL: URL = new URL(JET_KDC_PROXY_URL, window.location.href);
    connectionParameters.kdcProxyUrl = `${currentURL.href}/${connectionParameters.kdcToken}`;
    return of(connectionParameters);
  }
}
