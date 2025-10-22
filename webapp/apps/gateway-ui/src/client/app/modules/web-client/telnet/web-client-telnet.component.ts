import {
  Component,
  ElementRef,
  EventEmitter,
  Input,
  OnDestroy,
  OnInit,
  Output,
  Renderer2,
  ViewChild,
} from '@angular/core';
import { WebClientBaseComponent } from '@shared/bases/base-web-client.component';
import { GatewayAlertMessageService } from '@shared/components/gateway-alert-message/gateway-alert-message.service';
import { TelnetConnectionParameters } from '@shared/interfaces/connection-params.interfaces';
import { TelnetFormDataInput } from '@shared/interfaces/forms.interfaces';
import { ComponentStatus } from '@shared/models/component-status.model';
import { UtilsService } from '@shared/services/utils.service';
import { DefaultTelnetPort, WebClientService } from '@shared/services/web-client.service';
import { WebSessionService } from '@shared/services/web-session.service';
import { MessageService } from 'primeng/api';
import { EMPTY, from, Observable, of, Subject, throwError } from 'rxjs';
import { catchError, map, switchMap, takeUntil } from 'rxjs/operators';
import { v4 as uuidv4 } from 'uuid';
import '@devolutions/web-telnet-gui/dist/web-telnet-gui.js';
import {
  LoggingLevel,
  TelnetTerminal,
  TerminalConnectionStatus,
  loggingService as telnetLoggingService,
} from '@devolutions/web-telnet-gui';
import { DVL_TELNET_ICON, DVL_WARNING_ICON, JET_TELNET_URL } from '@gateway/app.constants';
import { AnalyticService, ProtocolString } from '@gateway/shared/services/analytic.service';
import { ExtractedHostnamePort } from '@shared/services/utils/string.service';

@Component({
  standalone: false,
  templateUrl: 'web-client-telnet.component.html',
  styleUrls: ['web-client-telnet.component.scss'],
  providers: [MessageService],
})
export class WebClientTelnetComponent extends WebClientBaseComponent implements OnInit, OnDestroy {
  @Input() webSessionId: string;
  @Output() componentStatus: EventEmitter<ComponentStatus> = new EventEmitter<ComponentStatus>();
  @Output() sizeChange: EventEmitter<void> = new EventEmitter<void>();

  @ViewChild('sessionTelnetContainer') sessionContainerElement: ElementRef;
  @ViewChild('webTelnetGuiTerminal') webGuiTerminal: ElementRef;

  formData: TelnetFormDataInput;
  clientError: string;

  rightToolbarButtons = [
    { label: 'Close Session', icon: 'dvl-icon dvl-icon-close', action: () => this.startTerminationProcess() },
  ];

  protected removeElement = new Subject();
  private remoteTerminal: TelnetTerminal;
  private unsubscribeTerminalEvent: () => void;

  constructor(
    private renderer: Renderer2,
    protected utils: UtilsService,
    protected gatewayAlertMessageService: GatewayAlertMessageService,
    private webSessionService: WebSessionService,
    private webClientService: WebClientService,
    protected analyticService: AnalyticService,
  ) {
    super(gatewayAlertMessageService, analyticService);
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
    this.handleSessionEndedOrError(TerminalConnectionStatus.closed);
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

  private removeRemoteTerminalListener(): void {
    this.unsubscribeTerminalEvent();
  }

  private initializeStatus(): void {
    this.currentStatus = {
      id: this.webSessionId,
      isInitialized: true,
      isDisabled: false,
      isDisabledByUser: false,
    };
  }

  private disableComponentStatus(): void {
    if (this.currentStatus.isDisabled) {
      return;
    }

    this.currentStatus.isDisabled = true;
    this.componentStatus.emit(this.currentStatus);
  }

  private startConnectionProcess(): void {
    if (!this.remoteTerminal) {
      return;
    }

    this.remoteTerminal.onStatusChange((v) => {
      if (v === TerminalConnectionStatus.connected) {
        // connected only indicates connection to Gateway is successful
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
          this.handleTelnetError(error.message);
          return EMPTY;
        }),
      )
      .subscribe();
  }

  private callConnect(connectionParameters: TelnetConnectionParameters) {
    return from(
      this.remoteTerminal.connect(
        connectionParameters.host,
        connectionParameters.port,
        null,
        connectionParameters.gatewayAddress + `?token=${connectionParameters.token}`,
        null,
      ),
    ).pipe(catchError((error) => throwError(error)));
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

    // Store the listener function for cleanup
    this.unsubscribeTerminalEvent = this.remoteTerminal.onStatusChange((status) => {
      switch (status) {
        case TerminalConnectionStatus.connected:
          this.handleSessionStarted();
          break;
        case TerminalConnectionStatus.failed:
        case TerminalConnectionStatus.closed:
        case TerminalConnectionStatus.timeout:
          this.handleSessionEndedOrError(status);
          break;
        default:
          break;
      }
    });
  }

  private handleSessionStarted(): void {
    this.handleClientConnectStarted();
    this.initializeStatus();
  }

  private handleSessionEndedOrError(status: TerminalConnectionStatus): void {
    if (document.fullscreenElement) {
      document.exitFullscreen().catch((err) => {
        console.error(`Error attempting to exit fullscreen: ${err}`);
      });
    }

    this.notifyUser(status);
    this.disableComponentStatus();
    super.webClientConnectionClosed();
  }

  private notifyUser(status: TerminalConnectionStatus): void {
    this.clientError = this.getMessage(status);

    const icon: string = status !== TerminalConnectionStatus.connected ? DVL_WARNING_ICON : DVL_TELNET_ICON;

    void this.webSessionService.updateWebSessionIcon(this.webSessionId, icon);
  }

  private handleSubscriptionError(error): void {
    console.error('Error in session event subscription', error);
  }

  private handleClientConnectStarted(): void {
    this.loading = false;
    void this.webSessionService.updateWebSessionIcon(this.webSessionId, DVL_TELNET_ICON);
    super.webClientConnectionSuccess();
  }

  private handleTelnetError(error: string): void {
    this.clientError = typeof error === 'string' ? error : this.getMessage(error);
    console.error(error);
    this.disableComponentStatus();

    void this.webSessionService.updateWebSessionIcon(this.webSessionId, DVL_WARNING_ICON);
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
