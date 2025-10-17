import {
  Component,
  CUSTOM_ELEMENTS_SCHEMA,
  ElementRef,
  EventEmitter,
  Input,
  OnDestroy,
  OnInit,
  Output,
  Renderer2,
  ViewChild,
} from '@angular/core';
import { LoggingLevel } from '@devolutions/terminal-shared';
import { loggingService as sshLoggingService, SSHTerminal, TerminalConnectionStatus } from '@devolutions/web-ssh-gui';
import { DVL_SSH_ICON, DVL_WARNING_ICON, JET_SSH_URL } from '@gateway/app.constants';
import { SessionToolbarComponent } from '@gateway/shared/components/session-toolbar/session-toolbar.component';
import { AnalyticService, ProtocolString } from '@gateway/shared/services/analytic.service';
import { WebClientBaseComponent, WebComponentReady } from '@shared/bases/base-web-client.component';
import { GatewayAlertMessageService } from '@shared/components/gateway-alert-message/gateway-alert-message.service';
import { SshConnectionParameters } from '@shared/interfaces/connection-params.interfaces';
import { SSHFormDataInput } from '@shared/interfaces/forms.interfaces';
import { ComponentStatus } from '@shared/models/component-status.model';
import { UtilsService } from '@shared/services/utils.service';
import { ExtractedHostnamePort } from '@shared/services/utils/string.service';
import { DefaultSshPort, WebClientService } from '@shared/services/web-client.service';
import { WebSessionService } from '@shared/services/web-session.service';
import { MessageService } from 'primeng/api';
import { ProgressSpinnerModule } from 'primeng/progressspinner';
import { EMPTY, from, Observable, of, Subject, throwError } from 'rxjs';
import { catchError, map, switchMap, takeUntil } from 'rxjs/operators';
import { v4 as uuidv4 } from 'uuid';

@Component({
  selector: 'gateway-web-client-ssh',
  templateUrl: 'web-client-ssh.component.html',
  styleUrls: ['web-client-ssh.component.scss'],
  providers: [MessageService],
  standalone: true,
  imports: [SessionToolbarComponent, ProgressSpinnerModule],
  schemas: [CUSTOM_ELEMENTS_SCHEMA],
})
export class WebClientSshComponent extends WebClientBaseComponent implements WebComponentReady, OnInit, OnDestroy {
  @Input() webSessionId: string;
  @Output() componentStatus: EventEmitter<ComponentStatus> = new EventEmitter<ComponentStatus>();
  @Output() sizeChange: EventEmitter<void> = new EventEmitter<void>();

  @ViewChild('sessionSshContainer') sessionContainerElement: ElementRef;
  @ViewChild('webSSHGuiTerminal') webGuiTerminal: ElementRef;

  formData: SSHFormDataInput;
  clientError: string;

  rightToolbarButtons = [
    { label: 'Close Session', icon: 'dvl-icon dvl-icon-close', action: () => this.startTerminationProcess() },
  ];

  protected removeElement = new Subject();
  private remoteTerminal: SSHTerminal;
  private remoteTerminalEventListener: () => void;

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
    sshLoggingService.setLevel(LoggingLevel.DEBUG);
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

    this.remoteTerminal = event.detail.sshTerminal;
    this.initSessionEventHandler();
    this.startConnectionProcess();
  }

  startTerminationProcess(): void {
    this.currentStatus.isDisabledByUser = true;
    this.handleSessionEndedOrError(TerminalConnectionStatus.failed);
    this.sendTerminateSessionCmd();
    this.disableComponentStatus();
  }

  sendTerminateSessionCmd(): void {
    if (!this.currentStatus.isInitialized) {
      return;
    }
    void this.remoteTerminal.close();
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
    if (this.remoteTerminalEventListener) {
      this.remoteTerminalEventListener();
    }
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
        switchMap((params) => this.webClientService.fetchSshToken(params)),
        switchMap((params) => this.callConnect(params)),
        catchError((error) => {
          this.handleSshError(error.message);
          return EMPTY;
        }),
      )
      .subscribe();
  }

  private callConnect(connectionParameters: SshConnectionParameters) {
    return from(
      this.remoteTerminal.connect({
        hostname: connectionParameters.host,
        port: connectionParameters.port,
        username: connectionParameters.username,
        proxyUrl: connectionParameters.gatewayAddress + `?token=${connectionParameters.token}`,
        passpharse: connectionParameters.privateKeyPassphrase ?? '',
        privateKey: connectionParameters.privateKey ?? '',
        password: connectionParameters.password ?? '',
        onHostKeyReceived: (_serverName, _fingerprint) => {
          return Promise.resolve(true);
        },
      }),
    ).pipe(catchError((error) => throwError(error)));
  }

  private getFormData(): Observable<void> {
    return from(this.webSessionService.getWebSession(this.webSessionId)).pipe(
      takeUntil(this.destroyed$),
      map((currentWebSession) => {
        this.formData = currentWebSession.data as SSHFormDataInput;
      }),
    );
  }

  private fetchParameters(formData: SSHFormDataInput): Observable<SshConnectionParameters> {
    const { hostname, username, password } = formData;

    const sessionId: string = uuidv4();
    const extractedData: ExtractedHostnamePort = this.utils.string.extractHostnameAndPort(hostname, DefaultSshPort);
    const gatewayHttpAddress: URL = new URL(JET_SSH_URL + `/${sessionId}`, window.location.href);
    const gatewayAddress: string = gatewayHttpAddress.toString().replace('http', 'ws');
    const privateKey: string | null = formData.extraData?.sshPrivateKey || null;
    const privateKeyPassphrase: string = formData.passphrase || null;
    const connectionParameters: SshConnectionParameters = {
      host: extractedData.hostname,
      username: username,
      password: password,
      port: extractedData.port,
      gatewayAddress: gatewayAddress,
      sessionId: sessionId,
      privateKey: privateKey,
      privateKeyPassphrase: privateKeyPassphrase,
    };
    return of(connectionParameters);
  }

  private initSessionEventHandler(): void {
    if (!this.remoteTerminal) {
      console.error('Remote terminal is not initialized.');
      return;
    }

    this.remoteTerminal.onStatusChange((status) => {
      switch (status) {
        case TerminalConnectionStatus.connected:
          this.handleSessionStarted();
          break;
        case TerminalConnectionStatus.failed:
        case TerminalConnectionStatus.closed:
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

    const icon: string = status !== TerminalConnectionStatus.connected ? DVL_WARNING_ICON : DVL_SSH_ICON;
    void this.webSessionService.updateWebSessionIcon(this.webSessionId, icon);
  }

  private handleSubscriptionError(error): void {
    console.error('Error in session event subscription', error);
  }

  private handleClientConnectStarted(): void {
    this.loading = false;
    void this.webSessionService.updateWebSessionIcon(this.webSessionId, DVL_SSH_ICON);
    super.webClientConnectionSuccess();
  }

  private handleSshError(error: string): void {
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
      default:
        return 'Unknown Error';
    }
  }

  protected getProtocol(): ProtocolString {
    return 'SSH';
  }
}
