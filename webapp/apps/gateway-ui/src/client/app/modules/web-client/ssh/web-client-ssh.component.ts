import { Component, ElementRef, Input, OnDestroy, OnInit, ViewChild } from '@angular/core';
import { LoggingLevel } from '@devolutions/terminal-shared';
import { SSHTerminal, loggingService as sshLoggingService, TerminalConnectionStatus } from '@devolutions/web-ssh-gui';
import { DVL_SSH_ICON, JET_SSH_URL } from '@gateway/app.constants';
import { AnalyticService, ProtocolString } from '@gateway/shared/services/analytic.service';
import { WebComponentReady } from '@shared/bases/base-web-client.component';
import { TerminalWebClientBaseComponent } from '@shared/bases/terminal-web-client-base.component';
import { GatewayAlertMessageService } from '@shared/components/gateway-alert-message/gateway-alert-message.service';
import { SshConnectionParameters } from '@shared/interfaces/connection-params.interfaces';
import { SSHFormDataInput } from '@shared/interfaces/forms.interfaces';
import { ExtractedHostnamePort } from '@shared/services/utils/string.service';
import { UtilsService } from '@shared/services/utils.service';
import { DefaultSshPort, WebClientService } from '@shared/services/web-client.service';
import { WebSessionService } from '@shared/services/web-session.service';
import { MessageService } from 'primeng/api';
import { EMPTY, from, Observable, of, throwError } from 'rxjs';
import { catchError, map, switchMap, takeUntil } from 'rxjs/operators';
import { v4 as uuidv4 } from 'uuid';

@Component({
  standalone: false,
  selector: 'gateway-web-client-ssh',
  templateUrl: 'web-client-ssh.component.html',
  styleUrls: ['web-client-ssh.component.scss'],
  providers: [MessageService],
})
export class WebClientSshComponent
  extends TerminalWebClientBaseComponent
  implements WebComponentReady, OnInit, OnDestroy
{
  @Input() webSessionId: string;

  @ViewChild('sessionSshContainer') sessionContainerElement: ElementRef;
  @ViewChild('webSSHGuiTerminal') webGuiTerminal: ElementRef;

  formData: SSHFormDataInput;

  private remoteTerminal: SSHTerminal;
  private remoteTerminalEventListener: () => void;

  constructor(
    protected utils: UtilsService,
    protected override gatewayAlertMessageService: GatewayAlertMessageService,
    webSessionService: WebSessionService,
    private webClientService: WebClientService,
    protected override analyticService: AnalyticService,
  ) {
    super(gatewayAlertMessageService, webSessionService, analyticService);
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
    this.handleSessionEnded(this.getMessage(TerminalConnectionStatus.failed));
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

  protected getSuccessIcon(): string {
    return DVL_SSH_ICON;
  }

  private removeRemoteTerminalListener(): void {
    if (this.remoteTerminalEventListener) {
      this.remoteTerminalEventListener();
    }
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
        switchMap((params) => this.webClientService.fetchSshToken(params)),
        switchMap((params) => this.callConnect(params)),
        catchError((error) => {
          this.handleConnectionError(error.message);
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
          this.handleClientConnectStarted();
          this.initializeStatus();
          break;
        case TerminalConnectionStatus.failed:
        case TerminalConnectionStatus.closed:
          this.handleSessionEnded(this.getMessage(status));
          break;
        default:
          break;
      }
    });
  }

  private getMessage(status: TerminalConnectionStatus): string {
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
