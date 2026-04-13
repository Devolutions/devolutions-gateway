import { Component, ElementRef, Input, OnDestroy, OnInit, ViewChild } from '@angular/core';
import { GatewayAlertMessageService } from '@shared/components/gateway-alert-message/gateway-alert-message.service';
import { TelnetConnectionParameters } from '@shared/interfaces/connection-params.interfaces';
import { TelnetFormDataInput } from '@shared/interfaces/forms.interfaces';
import { UtilsService } from '@shared/services/utils.service';
import { DefaultTelnetPort, WebClientService } from '@shared/services/web-client.service';
import { WebSessionService } from '@shared/services/web-session.service';
import { MessageService } from 'primeng/api';
import { EMPTY, from, Observable, of, throwError } from 'rxjs';
import { catchError, map, switchMap, takeUntil } from 'rxjs/operators';
import { v4 as uuidv4 } from 'uuid';
import '@devolutions/web-telnet-gui/dist/web-telnet-gui.js';
import {
  LoggingLevel,
  TelnetTerminal,
  TerminalConnectionStatus,
  loggingService as telnetLoggingService,
} from '@devolutions/web-telnet-gui';
import { DVL_TELNET_ICON, JET_TELNET_URL } from '@gateway/app.constants';
import { AnalyticService, ProtocolString } from '@gateway/shared/services/analytic.service';
import { TerminalWebClientBaseComponent } from '@shared/bases/terminal-web-client-base.component';
import { ExtractedHostnamePort } from '@shared/services/utils/string.service';

@Component({
  standalone: false,
  templateUrl: 'web-client-telnet.component.html',
  styleUrls: ['web-client-telnet.component.scss'],
  providers: [MessageService],
})
export class WebClientTelnetComponent extends TerminalWebClientBaseComponent implements OnInit, OnDestroy {
  @Input() webSessionId: string;

  @ViewChild('sessionTelnetContainer') sessionContainerElement: ElementRef;
  @ViewChild('webTelnetGuiTerminal') webGuiTerminal: ElementRef;

  formData: TelnetFormDataInput;

  rightToolbarButtons = [
    { label: 'Close Session', icon: 'dvl-icon dvl-icon-close', action: () => this.startTerminationProcess() },
  ];

  private remoteTerminal: TelnetTerminal;
  private unsubscribeTerminalEvent: () => void;

  constructor(
    protected utils: UtilsService,
    protected gatewayAlertMessageService: GatewayAlertMessageService,
    protected webSessionService: WebSessionService,
    protected webClientService: WebClientService,
    protected analyticService: AnalyticService,
  ) {
    super(gatewayAlertMessageService, webSessionService, analyticService);
  }

  ngOnInit(): void {
    telnetLoggingService.setLevel(LoggingLevel.FATAL);
    this.removeWebClientGuiElement();
  }

  ngOnDestroy(): void {
    this.removeRemoteTerminalListener();
    this.removeWebClientGuiElement();

    if (this.currentStatus.isInitialized && !this.currentStatus.isDisabled) {
      this.startTerminationProcess();
    }

    super.ngOnDestroy();
  }

  webComponentReady(event: CustomEvent, webSessionId: string): void {
    if (this.currentStatus.isInitialized || webSessionId !== this.webSessionId) {
      return;
    }

    this.remoteTerminal = event.detail.telnetTerminal;
    this.initSessionEventHandler();
    this.startConnectionProcess();
  }

  startTerminationProcess(): void {
    this.currentStatus.isDisabledByUser = true;
    this.sendTerminateSessionCmd();
    this.handleSessionEnded(this.getMessage(TerminalConnectionStatus.closed), false);
  }

  sendTerminateSessionCmd(): void {
    if (!this.currentStatus.isInitialized) {
      return;
    }
    this.currentStatus.isInitialized = false;
    this.remoteTerminal.close();
  }

  removeWebClientGuiElement(): void {
    this.removeElement.pipe(takeUntil(this.destroyed$)).subscribe({
      next: (): void => {
        if (this.webGuiTerminal?.nativeElement) {
          this.webGuiTerminal.nativeElement.remove();
        }
      },
      error: (err): void => {
        console.error('Error while removing element:', err);
      },
    });
  }

  protected getSuccessIcon(): string {
    return DVL_TELNET_ICON;
  }

  private removeRemoteTerminalListener(): void {
    this.unsubscribeTerminalEvent?.();
  }

  private startConnectionProcess(): void {
    if (!this.remoteTerminal) {
      return;
    }

    this.remoteTerminal.onStatusChange((v) => {
      if (v === TerminalConnectionStatus.connected) {
        this.remoteTerminal.writeToTerminal('connecting... \r\n');
      }
    });

    this.getFormData()
      .pipe(
        takeUntil(this.destroyed$),
        switchMap(() => this.fetchParameters(this.formData)),
        switchMap((params) => this.webClientService.fetchTelnetToken(params)),
        switchMap((params) => this.callConnect(params)),
        catchError((error) => {
          this.handleConnectionError(error.message);
          return EMPTY;
        }),
      )
      .subscribe();
  }

  private callConnect(connectionParameters: TelnetConnectionParameters) {
    const gatewayUrl = new URL(connectionParameters.gatewayAddress);
    if (connectionParameters.token && !gatewayUrl.searchParams.has('token')) {
      gatewayUrl.searchParams.set('token', connectionParameters.token);
    }
    const gatewayAddress: string = gatewayUrl.toString();

    return from(
      this.remoteTerminal.connect({
        hostname: connectionParameters.host,
        port: connectionParameters.port,
        username: null,
        password: null,
        proxyUrl: gatewayAddress,
      }),
    ).pipe(catchError((error) => throwError(() => error)));
  }

  private getFormData() {
    return from(this.webSessionService.getWebSession(this.webSessionId)).pipe(
      map((currentWebSession) => {
        this.formData = currentWebSession.data as TelnetFormDataInput;
      }),
    );
  }

  private fetchParameters(formData: TelnetFormDataInput): Observable<TelnetConnectionParameters> {
    const { hostname } = formData;

    const sessionId: string = uuidv4();
    const extractedData: ExtractedHostnamePort = this.utils.string.extractHostnameAndPort(hostname, DefaultTelnetPort);
    const gatewayHttpAddress: URL = new URL(JET_TELNET_URL + `/${sessionId}`, window.location.href);
    const gatewayAddress: string = gatewayHttpAddress.toString().replace('http', 'ws');

    const connectionParameters: TelnetConnectionParameters = {
      host: extractedData.hostname,
      port: extractedData.port,
      gatewayAddress: gatewayAddress,
      sessionId: sessionId,
    };
    return of(connectionParameters);
  }

  private initSessionEventHandler(): void {
    if (!this.remoteTerminal) {
      console.error('Remote terminal is not initialized.');
      return;
    }

    this.unsubscribeTerminalEvent = this.remoteTerminal.onStatusChange((status) => {
      switch (status) {
        case TerminalConnectionStatus.connected:
          this.handleClientConnectStarted();
          this.initializeStatus();
          break;
        case TerminalConnectionStatus.failed:
        case TerminalConnectionStatus.closed:
        case TerminalConnectionStatus.timeout:
          this.handleSessionEnded(this.getMessage(status));
          break;
        default:
          break;
      }
    });
  }

  private getMessage(status: TerminalConnectionStatus): string {
    //For translation 'UnknownError'
    //For translation 'ConnectionErrorPleaseVerifyYourConnectionSettings'
    //For translation 'SessionClosed'
    //For translation 'lblConnectionTimeout'
    if (typeof status === 'string') {
      return status;
    }

    switch (status) {
      case TerminalConnectionStatus.failed:
        return 'Connection error: Please verify your connection settings.';
      case TerminalConnectionStatus.closed:
        return 'Session closed';
      case TerminalConnectionStatus.timeout:
        return 'Connection timeout.';
      default:
        return 'Unknown Error';
    }
  }

  protected getProtocol(): ProtocolString {
    return 'Telnet';
  }
}
