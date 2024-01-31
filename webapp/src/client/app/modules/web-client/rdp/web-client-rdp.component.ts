import {
  AfterViewInit,
  Component,
  ElementRef,
  EventEmitter, HostListener,
  Input, OnDestroy,
  OnInit,
  Output,
  ViewChild,
  Renderer2
} from '@angular/core';
import {from, noop, Observable, Subject} from "rxjs";
import {catchError, map, mergeMap, switchMap, takeUntil, tap} from 'rxjs/operators';
import {MessageService} from "primeng/api";

import { WebClientBaseComponent } from "@shared/bases/base-web-client.component";
import {DefaultRDPPort, IronRDPConnectionParameters} from "@shared/services/web-client.service";
import { ApiService } from "@shared/services/api.service";
import {GatewayAlertMessageService} from "@shared/components/gateway-alert-message/gateway-alert-message.service";
import {ComponentStatus} from "@shared/models/component-status.model";
import {WebSessionService} from "@shared/services/web-session.service";
import {UtilsService} from "@shared/services/utils.service";

import {UserInteraction, SessionEvent, UserIronRdpError} from '@devolutions/iron-remote-gui';
import '@devolutions/iron-remote-gui/iron-remote-gui.umd.cjs';

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

  @ViewChild('sessionContainer') sessionContainerElement: ElementRef;
  @ViewChild('ironGuiElement') ironGuiElement: ElementRef;

  JET_RDP_URL: string = '/jet/rdp';
  screenScale = ScreenScale;
  currentStatus: ComponentStatus;
  inputFormData: any;
  rdpError: string;
  isFullScreenMode: boolean = false;
  showToolbarDiv: boolean = true;
  loading: boolean = true;

  protected removeElement: Subject<any> = new Subject();
  private remoteClient: UserInteraction;

  constructor(private renderer: Renderer2,
              private apiService: ApiService,
              protected utils: UtilsService,
              protected gatewayAlertMessageService: GatewayAlertMessageService,
              private webSessionService: WebSessionService) {
    super(gatewayAlertMessageService);
  }

  @HostListener('document:mousemove', ['$event'])
  onMouseMove(event: MouseEvent): void {
    this.handleSessionToolbarDisplay(event);
  }

  @HostListener('document:fullscreenchange')
  onFullScreenChange(): void {
    this.handleOnFullScreenEvent();
  }

  ngOnInit(): void {
    this.removeWebClientGuiElement();
    this.initializeStatus();
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
    this.currentStatus.isDisabledByUser = true;
  }

  scaleTo(scale: ScreenScale): void {
    if (scale === ScreenScale.Full) {
        this.toggleFullscreen();
    } else {
      this.remoteClient.setScale(scale);
    }
  }

  removeWebClientGuiElement(): void {
    this.removeElement
      .pipe(takeUntil(this.destroyed$))
      .subscribe((): void => {
        this.ironGuiElement.nativeElement.remove();
      });
  }

  private initializeStatus(): void {
    this.currentStatus = {
      isInitialized: false,
      isDisabled: false,
      isDisabledByUser: false,
      tabIndex: this.tabIndex
    }
  }

  private handleOnFullScreenEvent(): void {
    if (!document.fullscreenElement) {
      this.exitFullScreenMode()
    }
  }

  private handleSessionToolbarDisplay(event: MouseEvent): void {
    if (!document.fullscreenElement) {
      return;
    }

    if (event.clientY == 0) {
      this.showToolbarDiv = true;
    } else if (event.clientY > 44) {
      this.showToolbarDiv = false;
    }
  }

  private toggleFullscreen(): void {
    this.isFullScreenMode = !this.isFullScreenMode;

    if (!document.fullscreenElement) {
      this.enterFullScreenMode();
    } else {
      document.exitFullscreen();
    }
  }

  private enterFullScreenMode(): void {
    if (document.fullscreenElement) {
      return;
    }
    const sessionContainerElement = this.sessionContainerElement.nativeElement;

    sessionContainerElement.requestFullscreen().then(() => {
      // using .Full screen scale causes scrollbars, Fit works better in this case. KAH Jan 2024
      this.remoteClient.setScale(ScreenScale.Fit);
    }).catch((err: any) => {
      this.isFullScreenMode = false;
      console.error(`Error attempting to enable fullscreen mode: ${err.message} (${err.name})`);
    });
  }

  private exitFullScreenMode(): void {
    this.isFullScreenMode = false;
    this.showToolbarDiv = true;

    const sessionContainerElement = this.sessionContainerElement.nativeElement;
    const sessionToolbarElement = sessionContainerElement.querySelector('#sessionToolbar');
    if (sessionToolbarElement) {
      this.renderer.removeClass(sessionToolbarElement, 'session-toolbar-layer');
    }
    this.remoteClient.setScale(ScreenScale.Fit);
  }

  private initiateRemoteClientListener(): void {
    this.ironGuiElement.nativeElement.addEventListener('ready', (event: Event) => this.readyRemoteClientEventListener(event));
  }

  private removeRemoteClientListener(): void {
    if (this.ironGuiElement && this.readyRemoteClientEventListener) {
      this.ironGuiElement.nativeElement.removeEventListener('ready', this.readyRemoteClientEventListener);
    }
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
        const extractedData = this.utils.string.extractDomain(username);
        const gatewayHttpAddress: URL = new URL(this.JET_RDP_URL, window.location.href);
        const websocketUrl: string = gatewayHttpAddress.toString().replace("http", "ws");

        const connectionParameters: IronRDPConnectionParameters = {
          username: extractedData.username,
          password: password,
          host: hostname,
          domain: extractedData.domain,
          gatewayAddress: websocketUrl,
          screenSize: desktopSize,
          preConnectionBlob: preConnectionBlob,
          kdcProxyUrl: kdcProxyUrl
        };
        console.log('Debug: connectionParameters', connectionParameters)
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
            this.currentStatus.isInitialized = true;
            break;
          case SessionEventType.TERMINATED:
            this.currentStatus.isDisabled = true;
            this.handleIronRDPTerminated(event.data);
            break;
          case SessionEventType.ERROR:
            this.currentStatus.isDisabled = true;
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
    this.currentStatus.isDisabled = true;
    this.componentStatus.emit(this.currentStatus);
  }

  private handleIronRDPError(error: UserIronRdpError | string): void {
    this.notifyUserAboutError(error);
    this.currentStatus.isDisabled = true;
    this.componentStatus.emit(this.currentStatus);
  }

  private notifyUserAboutError(error: UserIronRdpError | string): void {
    this.tabIndex = this.currentStatus.tabIndex;

    if (typeof error === 'string') {
      this.rdpError = error;
    } else {
      this.rdpError = this.getMessage(error.kind());
    }
    this.webSessionService.updateWebSessionIcon(this.tabIndex, 'dvl-icon-warning').then(noop);
  }

  private notifyUserAboutConnectionClosed(error: UserIronRdpError | string): void {
    this.rdpError = typeof error === 'string' ? error : this.getMessage(error.kind());
    this.webSessionService.updateWebSessionIcon(this.tabIndex, 'dvl-icon-warning').then(noop);
  }

  private getMessage(errorKind: UserIronRdpErrorKind): string {
    //For translation 'UnknownError'
    //For translation 'ConnectionErrorPleaseVerifyYourConnectionSettings'
    //For translation 'AccessDenied'
    //For translation 'ConnectionErrorPleaseVerifyYourConnectionSettings'

    const errorMessages = {
      [UserIronRdpErrorKind.General]: 'Unknown Error',
      [UserIronRdpErrorKind.WrongPassword]: 'Connection error: Please verify your connection settings.',
      [UserIronRdpErrorKind.LogonFailure]: 'Connection error: Please verify your connection settings.',
      [UserIronRdpErrorKind.AccessDenied]: 'Access denied',
    };
    return errorMessages[errorKind] || 'Connection error: Please verify your connection settings.';
  }
}
