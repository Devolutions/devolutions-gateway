import {
  AfterViewInit,
  Component,
  ElementRef,
  EventEmitter,
  Input, OnDestroy,
  OnInit,
  Output,
  ViewChild
} from '@angular/core';
import {from, Observable, Subject} from "rxjs";
import {catchError, map, mergeMap, switchMap, takeUntil, tap} from 'rxjs/operators';
import {UserInteraction, SessionEvent, UserIronRdpError} from '@devolutions/iron-remote-gui';
import '@devolutions/iron-remote-gui/iron-remote-gui.umd.cjs';
import { WebClientBaseComponent } from "@shared/bases/base-web-client.component";
import {DefaultRDPPort, IronRDPConnectionParameters} from "@shared/services/web-client.service";
import { ApiService } from "@shared/services/api.service";
import {GatewayAlertMessageService} from "@shared/components/gateway-alert-message/gateway-alert-message.service";
import {ComponentStatus} from "@shared/models/component-status.model";
import {MessageService} from "primeng/api";
import {WebSessionService} from "@shared/services/web-session.service";

export enum SSPIType {
  Kerberos = 0,
  Negotiate = 1,
  Ntlm = 2,
}
enum ScreenScale {
  Fit = 1,
  Full = 2,
  Real = 3,
}
enum SessionEventType {
  STARTED = 0,
  TERMINATED = 1,
  ERROR = 2
}
enum UserIronRdpErrorKind {
  General = 0,
  WrongPassword = 1,
  LogonFailure = 2,
  AccessDenied = 3,
  RDCleanPath = 4,
  ProxyConnect = 5
}

@Component({
  templateUrl: 'web-client-rdp.component.html',
  styleUrls: ['web-client-rdp.component.scss'],
  providers: [MessageService]
})
export class WebClientRdpComponent extends WebClientBaseComponent implements  OnInit,
                                                                              AfterViewInit,
                                                                              OnDestroy {

  @Input() tabIndex: number | undefined;
  @Output() componentStatus: EventEmitter<ComponentStatus> = new EventEmitter<ComponentStatus>();
  @ViewChild('ironGuiElement') ironGuiElement: ElementRef;

  JET_RDP_URL: string = '/jet/rdp';
  loading: boolean = true;
  screenScale = ScreenScale;
  fullScreen: boolean;
  inputFormData: any;
  status: ComponentStatus;
  rdpError: string;

  protected removeElement: Subject<any> = new Subject();
  private remoteClient: UserInteraction;

  constructor(private apiService: ApiService,
              protected gatewayAlertMessageService: GatewayAlertMessageService,
              private webSessionService: WebSessionService) {
    super(gatewayAlertMessageService);
  }

  ngOnInit(): void {
    this.removeWebClientGuiElement();

    this.status = {
      isInitialized: false,
      isDisabled: false,
      isDisabledByUser: false,
      tabIndex: this.tabIndex
    }
  }

  ngAfterViewInit(): void {
    this.initiateRemoteClientListener();
  }

  ngOnDestroy(): void {
    this.removeRemoteClientListener();
    this.removeWebClientGuiElement();
    super.ngOnDestroy();
  }

  sendWindowsKey(): void {
    this.remoteClient.metaKey();
  }

  sendCtrlAltDel(): void {
    this.remoteClient.ctrlAltDel();
  }

  sendTerminateSessionCmd(): void {
    // shutdowns the session, not the server
    this.remoteClient.shutdown();
    this.status.isDisabledByUser = true;
  }

  scaleTo(scale: ScreenScale): void {
    this.fullScreen = scale === ScreenScale.Full;
    this.remoteClient.setScale(scale);
  }

  private initiateRemoteClientListener(): void {
    this.ironGuiElement.nativeElement.addEventListener('ready', (event: Event) => this.readyRemoteClientEventListener(event));
  }

  private removeRemoteClientListener(): void {
    if (this.ironGuiElement && this.readyRemoteClientEventListener) {
      this.ironGuiElement.nativeElement.removeEventListener('ready', this.readyRemoteClientEventListener);
    }
  }

  removeWebClientGuiElement(): void {
    this.removeElement
      .pipe(takeUntil(this.destroyed$))
      .subscribe((): void => {
        this.ironGuiElement.nativeElement.remove();
      });
  }

  private readyRemoteClientEventListener(event: Event): void {
    const customEvent = event as CustomEvent;
    this.remoteClient = customEvent.detail.irgUserInteraction;

    this.initSessionEventHandler();
    this.startConnectionProcess();
  }

  private startConnectionProcess(): void {
    this.getCredentials()
      .pipe(
        takeUntil(this.destroyed$),
        mergeMap(connectionParameters => this.callConnect(connectionParameters))
      ).subscribe(
        () => {},
        (error) => {
          this.notifyUserAboutError(error.message);
        });
  }

  private getCredentials(): Observable<IronRDPConnectionParameters> {
    return this.getFormData().pipe(
      switchMap((connectionParameters)=> this.fetchToken(connectionParameters)),
      map((connectionParameters) => connectionParameters),
      catchError(err => {
        throw err;
      })
    );
  }

  private getFormData(): Observable<IronRDPConnectionParameters> {
    return from(this.webSessionService.getWebSession(this.tabIndex)).pipe(
      map(currentWebSession => {
        this.inputFormData = currentWebSession.data;
        const { hostname, username, password, desktopSize, preConnectionBlob, kdcProxyUrl } = this.inputFormData;
        const domain: string = '';

        const gatewayHttpAddress: URL = new URL(this.JET_RDP_URL, window.location.href);
        const websocketUrl: string = gatewayHttpAddress.toString().replace("http", "ws");

        const connectionParameters: IronRDPConnectionParameters = {
          username: username,
          password: password,
          host: hostname,
          domain: domain,
          gatewayAddress: websocketUrl,
          screenSize: desktopSize,
          preConnectionBlob: preConnectionBlob,
          kdcProxyUrl: kdcProxyUrl
        };

        return connectionParameters;
      })
    );
  }

  private callConnect(connectionParameters: IronRDPConnectionParameters): Observable<void> {
    return this.remoteClient.connect(
      connectionParameters.username,
      connectionParameters.password,
      connectionParameters.host,
      connectionParameters.gatewayAddress,
      connectionParameters.domain,
      connectionParameters.token,
      connectionParameters.screenSize,
      connectionParameters.preConnectionBlob,
      connectionParameters.kdcProxyUrl
    ).pipe(
      takeUntil(this.destroyed$),
      map(connectionData => {
        //connectionData - NewSessionInfo may be useful in the future.
      })
    );
  }

  private fetchToken(connectionParameters: IronRDPConnectionParameters): Observable<IronRDPConnectionParameters> {
    //TODO create a proper model
    const data = {
      "content_type": "ASSOCIATION",
      "protocol": "rdp",
      "destination": `tcp://${connectionParameters.host}:${DefaultRDPPort}`,
      "lifetime": 60,
      "session_id": "cbd67c3b-6bb1-492d-a7be-2af0a5e63f6a"
    }

    return this.apiService.generateSessionToken(data).pipe(
      takeUntil(this.destroyed$),
      tap((token: string) => connectionParameters.token = token),
      map(() => connectionParameters),
      catchError(err => {
        console.error('Fetch Token Error:', err);
        throw err;
      })
    );
  }

  private initSessionEventHandler(): void {
    this.remoteClient.sessionListener
      .pipe(takeUntil(this.destroyed$))
      .subscribe((event: SessionEvent): void => {
        switch (event.type) {
          case SessionEventType.STARTED:
            this.handleIronRDPConnectStarted();
            this.status.isInitialized = true;
            break;
          case SessionEventType.TERMINATED:
            this.status.isDisabled = true;
            this.handleIronRDPTerminated(event.data);
            break;
          case SessionEventType.ERROR:
            this.status.isDisabled = true;
            this.handleIronRDPError(event.data);
            break;
        }
    });
  }

  private handleIronRDPConnectStarted(): void {
    this.loading = false;
    this.remoteClient.setVisibility(true);
    this.webClientConnectionSuccess();
  }

  private handleIronRDPTerminated(data: UserIronRdpError | string): void {
    this.notifyUserAboutConnectionClosed(data);
    this.status.isDisabled = true;
    this.componentStatus.emit(this.status);
  }

  private handleIronRDPError(error: UserIronRdpError | string): void {
    this.notifyUserAboutError(error);
    this.status.isDisabled = true;
    this.componentStatus.emit(this.status);
  }

  private notifyUserAboutError(error: UserIronRdpError | string): void {
    this.tabIndex = this.status.tabIndex;

    if (typeof error === 'string') {
      this.rdpError = error;
    } else {
      this.rdpError = this.getMessage(error.kind());
    }
  }

  private notifyUserAboutConnectionClosed(error: UserIronRdpError | string): void {
    this.rdpError = typeof error === 'string' ? error : this.getMessage(error.kind());
  }

  private getMessage(type: UserIronRdpErrorKind): string {
    switch (type) {
      case UserIronRdpErrorKind.General:
        //For translation 'UnknownError'
        return 'Unknown Error';
        break;
      case UserIronRdpErrorKind.WrongPassword:
      case UserIronRdpErrorKind.LogonFailure:
        //For translation 'ConnectionErrorPleaseVerifyYourConnectionSettings'
        return 'Connection error: Please verify your connection settings.';
        break;
      case UserIronRdpErrorKind.AccessDenied:
        //For translation 'AccessDenied'
        return 'Access denied';
        break;
      default:
        //For translation 'ConnectionErrorPleaseVerifyYourConnectionSettings'
        return 'Connection error: Please verify your connection settings.';
    }
  }
}
