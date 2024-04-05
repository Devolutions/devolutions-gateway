import {
  Component,
  ElementRef,
  EventEmitter,
  Input,
  OnDestroy,
  OnInit,
  Output,
  Renderer2,
  ViewChild
} from "@angular/core";
import {v4 as uuidv4} from "uuid";
import {MessageService} from "primeng/api";
import {EMPTY, from, Observable, of, Subject, throwError} from "rxjs";
import {catchError, map, switchMap, takeUntil} from "rxjs/operators";

import {WebClientBaseComponent} from "@shared/bases/base-web-client.component";
import {UtilsService} from "@shared/services/utils.service";
import {GatewayAlertMessageService} from "@shared/components/gateway-alert-message/gateway-alert-message.service";
import {WebSessionService} from "@shared/services/web-session.service";
import {DefaultSshPort, WebClientService} from "@shared/services/web-client.service";
import {ComponentStatus} from "@shared/models/component-status.model";
import {SSHFormDataInput} from "@shared/interfaces/forms.interfaces";
import {SshConnectionParameters} from "@shared/interfaces/connection-params.interfaces";

import {
  LoggingLevel,
  loggingService as sshLoggingService,
  SSHTerminal,
  TerminalConnectionStatus
} from "@devolutions/web-ssh-gui";
import {ExtractedHostnamePort} from "@shared/services/utils/string.service";

@Component({
  templateUrl: 'web-client-ssh.component.html',
  styleUrls: ['web-client-ssh.component.scss'],
  providers: [MessageService]
})
export class WebClientSshComponent extends WebClientBaseComponent implements OnInit,
                                                                              OnDestroy {

  @Input() webSessionId: string;
  @Output() componentStatus: EventEmitter<ComponentStatus> = new EventEmitter<ComponentStatus>();
  @Output() sizeChange: EventEmitter<void> = new EventEmitter<void>();

  @ViewChild('sessionSshContainer') sessionContainerElement: ElementRef;
  @ViewChild('web-ssh-gui') webGuiTerminal: ElementRef;

  static DVL_SSH_ICON: string = 'dvl-icon-entry-session-ssh';
  static JET_SSH_URL: string = '/jet/fwd/tcp';

  currentStatus: ComponentStatus;
  inputFormData: SSHFormDataInput;
  clientError: string;
  loading: boolean = true;

  rightToolbarButtons = [
    { label: 'Close Session',
      icon: 'dvl-icon dvl-icon-close',
      action: () => this.startTerminationProcess() },
  ];

  protected removeElement: Subject<any> = new Subject();
  private remoteTerminal: SSHTerminal;
  private remoteTerminalEventListener: () => void;

  constructor(private renderer: Renderer2,
              protected utils: UtilsService,
              protected gatewayAlertMessageService: GatewayAlertMessageService,
              private webSessionService: WebSessionService,
              private webClientService: WebClientService) {
    super(gatewayAlertMessageService);
  }

  ngOnInit(): void {
    sshLoggingService.setLevel(LoggingLevel.FATAL)
    this.removeWebClientGuiElement();
    this.initializeStatus();

    this.initiateRemoteClientListener();
  }

  ngOnDestroy(): void {
    this.removeRemoteTerminalListener();
    this.removeWebClientGuiElement();

    if (this.currentStatus.isInitialized && !this.currentStatus.isDisabled) {
      this.startTerminationProcess();
    }

    super.ngOnDestroy();
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
    this.currentStatus.isInitialized = false;
    this.remoteTerminal.close();
  }

  removeWebClientGuiElement(): void {
    this.removeElement
      .pipe(takeUntil(this.destroyed$))
      .subscribe({
        next: (): void => {
          if (this.webGuiTerminal && this.webGuiTerminal.nativeElement) {
            this.webGuiTerminal.nativeElement.remove();
          }
        },
        error: (err): void => {
          console.error('Error while removing element:', err);
        }
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
      isInitialized: false,
      isDisabled: false,
      isDisabledByUser: false,
    }
  }

  private disableComponentStatus(): void {
    this.currentStatus.isDisabled = true;
    this.componentStatus.emit(this.currentStatus);
  }

  private initiateRemoteClientListener(): void {
    this.remoteTerminalEventListener = this.renderer.listen('window', 'sshInitialized', (event) => {
      if (this.currentStatus.isInitialized) {
        return;
      }
      this.webComponentReady(event);
    });
  }

  private webComponentReady(event: any): void {
    this.remoteTerminal = event.detail.sshTerminal;
    this.initSessionEventHandler();
    this.startConnectionProcess();
  }

  private startConnectionProcess(): void {
    if (!this.remoteTerminal) {
      return;
    }

    this.remoteTerminal.status.subscribe((v) => {
      if (v === TerminalConnectionStatus.connected) {
        // connected only indicates connection to Gateway is successful
        this.remoteTerminal.writeToTerminal('connecting... \r\n')
      }
    });

    this.getFormData().pipe(
      takeUntil(this.destroyed$),
      switchMap(()=> this.fetchParameters(this.inputFormData)),
      switchMap(params=> this.webClientService.fetchSshToken(params)),
      switchMap(params => this.callConnect(params)),
      catchError(error => {
        this.handleSshError(error.message);
        return EMPTY;
      })
    ).subscribe();
  }

  private callConnect(connectionParameters: SshConnectionParameters): Observable<any> {
    return from(
      this.remoteTerminal.connect(
        connectionParameters.host,
        connectionParameters.port,
        connectionParameters.username,
        connectionParameters.gatewayAddress+`?token=${connectionParameters.token}`,
        connectionParameters.password,
        connectionParameters.privateKey,
      )
    ).pipe(
      catchError(error => throwError(error))
    );
  }

  private getFormData(): Observable<void> {
    return from(this.webSessionService.getWebSession(this.webSessionId)).pipe(
      map(currentWebSession => this.inputFormData = currentWebSession.data)
    );
  }

  private fetchParameters(formData: SSHFormDataInput): Observable<SshConnectionParameters> {
    const { hostname, username, password } = formData;

    const sessionId: string = uuidv4();
    const extractedData: ExtractedHostnamePort = this.utils.string.extractHostnameAndPort(hostname, DefaultSshPort);
    const gatewayHttpAddress: URL = new URL(WebClientSshComponent.JET_SSH_URL+`/${sessionId}`, window.location.href);
    const gatewayAddress: string = gatewayHttpAddress.toString().replace("http", "ws");
    const privateKey: string | null = formData.extraData?.sshPrivateKey || null;

    const connectionParameters: SshConnectionParameters = {
      host: extractedData.hostname,
      username: username,
      password: password,
      port: extractedData.port,
      gatewayAddress: gatewayAddress,
      sessionId: sessionId,
      privateKey: privateKey
    }
    return of(connectionParameters);
  }

  private initSessionEventHandler(): void {
    if (!this.remoteTerminal) {
      console.error('Remote terminal is not initialized.');
      return;
    }

    this.remoteTerminal.status.subscribe({
      next: (status): void => {
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
      },
      error: (err) => this.handleSubscriptionError(err)
    });
  }

  private handleSessionStarted(): void {
    this.handleClientConnectStarted();
    this.currentStatus.isInitialized = true;
  }

  private handleSessionEndedOrError(status: TerminalConnectionStatus): void {
    if (document.fullscreenElement) {
      document.exitFullscreen().catch(err => {
        console.error(`Error attempting to exit fullscreen: ${err}`);
      });
    }

    this.notifyUser(status);
    this.disableComponentStatus();
  }

  private notifyUser(status: TerminalConnectionStatus): void {
    this.clientError = this.getMessage(status);

    const icon: string = status !== TerminalConnectionStatus.connected ?
      WebClientSshComponent.DVL_WARNING_ICON :
      WebClientSshComponent.DVL_SSH_ICON;

    this.webSessionService.updateWebSessionIcon(this.webSessionId, icon);
  }

  private handleSubscriptionError(error: any): void {
    console.error('Error in session event subscription', error);
  }

  private handleClientConnectStarted(): void {
    this.loading = false;
    this.webSessionService.updateWebSessionIcon(this.webSessionId, WebClientSshComponent.DVL_SSH_ICON);
  }

  private handleSshError(error: string): void {
    this.clientError = typeof error === 'string' ? error : this.getMessage(error);
    console.error(error);
    this.disableComponentStatus();

    this.webSessionService.updateWebSessionIcon(this.webSessionId, WebClientSshComponent.DVL_WARNING_ICON);
  }

  private getMessage(status: TerminalConnectionStatus): string {
    //For translation 'UnknownError'
    //For translation 'ConnectionErrorPleaseVerifyYourConnectionSettings'
    //For translation 'SessionClosed'
    //For translation 'lblConnectionTimeout'
    if (typeof status === "string") {
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
}
