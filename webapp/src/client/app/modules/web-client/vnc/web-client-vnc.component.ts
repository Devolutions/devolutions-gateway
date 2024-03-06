import {
  AfterViewInit,
  Component, ElementRef,
  EventEmitter, HostListener,
  Input,
  OnDestroy,
  OnInit,
  Output,
  Renderer2,
  ViewChild
} from "@angular/core";
import {MessageService} from "primeng/api";
import {EMPTY, from, Observable, of, Subject} from "rxjs";
import {catchError, map, switchMap, takeUntil} from "rxjs/operators";

import {WebClientBaseComponent} from "@shared/bases/base-web-client.component";
import {ComponentStatus} from "@shared/models/component-status.model";
import {ScreenSize} from "@shared/enums/screen-size.enum";
import {ScreenScale} from "@shared/enums/screen-scale.enum";
import {SessionEventType} from "@shared/enums/session-event-type.enum";
import {UtilsService} from "@shared/services/utils.service";
import {GatewayAlertMessageService} from "@shared/components/gateway-alert-message/gateway-alert-message.service";
import {WebSessionService} from "@shared/services/web-session.service";
import {DefaultVncPort, WebClientService} from "@shared/services/web-client.service";
import {VncFormDataInput} from "@shared/interfaces/forms.interfaces";
import {IronVNCConnectionParameters} from "@shared/interfaces/connection-params.interfaces";

import {UserInteraction, SessionEvent, UserIronRdpError, DesktopSize} from '@devolutions/iron-remote-gui-vnc';
import '@devolutions/iron-remote-gui-vnc/iron-remote-gui-vnc.umd.cjs';
import {v4 as uuidv4} from "uuid";
import {ExtractedHostnamePort} from "@shared/services/utils/string.service";

enum UserIronRdpErrorKind {
  General = 0,
  WrongPassword = 1,
  LogonFailure = 2,
  AccessDenied = 3,
  RDCleanPath = 4,
  ProxyConnect = 5
}

@Component({
  templateUrl: 'web-client-vnc.component.html',
  styleUrls: ['web-client-vnc.component.scss'],
  providers: [MessageService]
})
export class WebClientVncComponent extends WebClientBaseComponent implements  OnInit,
                                                                              AfterViewInit,
                                                                              OnDestroy {
  @Input() webSessionId: string;
  @Output() componentStatus: EventEmitter<ComponentStatus> = new EventEmitter<ComponentStatus>();
  @Output() sizeChange: EventEmitter<void> = new EventEmitter<void>();

  @ViewChild('sessionVncContainer') sessionContainerElement: ElementRef;
  @ViewChild('ironGuiElementVnc') ironGuiElement: ElementRef;

  static DVL_VNC_ICON: string = 'dvl-icon-entry-session-vnc';
  static DVL_WARNING_ICON: string = 'dvl-icon-warning';
  static JET_VNC_URL: string = '/jet/fwd/tcp';

  screenScale = ScreenScale;
  currentStatus: ComponentStatus;
  inputFormData: VncFormDataInput;
  clientError: string;
  isFullScreenMode: boolean = false;
  showToolbarDiv: boolean = true;
  loading: boolean = true;

  protected removeElement: Subject<any> = new Subject();
  private remoteClient: UserInteraction;
  private remoteClientEventListener: (event: Event) => void;

  constructor(private renderer: Renderer2,
              protected utils: UtilsService,
              protected gatewayAlertMessageService: GatewayAlertMessageService,
              private webSessionService: WebSessionService,
              private webClientService: WebClientService) {
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

  startTerminationProcess(): void {
    this.sendTerminateSessionCmd();
    this.currentStatus.isDisabledByUser = true;
    this.disableComponentStatus();
  }

  sendTerminateSessionCmd(): void {
    // shutdowns the session, not the server. Jan 2024 KAH.
    this.remoteClient.shutdown();
  }

  scaleTo(scale: ScreenScale): void {
    scale === ScreenScale.Full ? this.toggleFullscreen() : this.remoteClient.setScale(scale);
  }

  removeWebClientGuiElement(): void {
    this.removeElement
      .pipe(takeUntil(this.destroyed$))
      .subscribe({
        next: (): void => {
          if (this.ironGuiElement && this.ironGuiElement.nativeElement) {
            this.ironGuiElement.nativeElement.remove();
          }
        },
        error: (err): void => {
          console.error('Error while removing element:', err);
        }
      });
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

  private handleOnFullScreenEvent(): void {
    if (!document.fullscreenElement) {
      this.handleExitFullScreenEvent()
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
    !document.fullscreenElement ? this.enterFullScreen() : this.exitFullScreen();
  }

  private async enterFullScreen(): Promise<void>  {
    if (document.fullscreenElement) {
      return;
    }

    try {
      const sessionContainerElement = this.sessionContainerElement.nativeElement;
      await sessionContainerElement.requestFullscreen();
    } catch (err: any) {
      this.isFullScreenMode = false;
      console.error(`Error attempting to enable fullscreen mode: ${err.message} (${err.name})`);
    }
  }

  private exitFullScreen(): void {
    if (document.fullscreenElement) {
      document.exitFullscreen().catch(err => {
        console.error(`Error attempting to exit fullscreen: ${err}`);
      });
    }
  }

  private handleExitFullScreenEvent(): void {
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
    this.remoteClientEventListener = (event: Event) => this.readyRemoteClientEventListener(event);
    this.renderer.listen(this.ironGuiElement.nativeElement, 'ready', this.remoteClientEventListener);
  }

  private removeRemoteClientListener(): void {
    if (this.ironGuiElement && this.remoteClientEventListener) {
      this.renderer.destroy();
    }
  }

  private readyRemoteClientEventListener(event: Event): void {
    const customEvent: CustomEvent<any> = event as CustomEvent;
    this.remoteClient = customEvent.detail.irgUserInteraction;

    this.initSessionEventHandler();
    this.startConnectionProcess();
  }

  private startConnectionProcess(): void {
    this.getFormData().pipe(
      takeUntil(this.destroyed$),
      switchMap(()=> this.setScreenSizeScale(this.inputFormData.screenSize)),
      switchMap(()=> this.fetchParameters(this.inputFormData)),
      switchMap((params)=> this.fetchTokens(params)),
      switchMap(params => this.callConnect(params)),
      catchError(error => {
        console.error(error.message);
        this.handleIronRDPError(error.message);
        return EMPTY;
      })
    ).subscribe();
  }

  private getFormData(): Observable<void> {
    return from(this.webSessionService.getWebSession(this.webSessionId)).pipe(
      map(currentWebSession => this.inputFormData = currentWebSession.data)
    );
  }

  private fetchParameters(formData: VncFormDataInput): Observable<IronVNCConnectionParameters> {
    const { hostname, username, password } = formData;
    const extractedData: ExtractedHostnamePort = this.utils.string.extractHostnameAndPort(hostname, DefaultVncPort);

    const sessionId: string = uuidv4();
    const gatewayHttpAddress: URL = new URL(WebClientVncComponent.JET_VNC_URL+`/${sessionId}`, window.location.href);
    const gatewayAddress: string = gatewayHttpAddress.toString().replace("http", "ws");

    const desktopScreenSize: DesktopSize = this.webClientService.getDesktopSize(this.inputFormData) ??
      this.webSessionService.getWebSessionScreenSizeSnapshot();

    const connectionParameters: IronVNCConnectionParameters = {
      username: username ?? '',
      password: password ?? '',
      host: extractedData.hostname,
      port: extractedData.port,
      domain: '',
      gatewayAddress: gatewayAddress,
      screenSize: desktopScreenSize,
      preConnectionBlob: '',
      kdcUrl: '',
      sessionId: sessionId
    };
    return of(connectionParameters);
  }

  fetchTokens(params: IronVNCConnectionParameters): Observable<IronVNCConnectionParameters> {
    return this.webClientService.fetchVncToken(params);
  }

  private setScreenSizeScale(screenSize: ScreenSize): Observable<void> {
    if (screenSize === ScreenSize.FullScreen) {
      this.scaleTo(this.screenScale.Full);
    }
    return of(undefined);
  }

  private callConnect(connectionParameters: IronVNCConnectionParameters): Observable<void> {
    this.remoteClient.setKeyboardUnicodeMode(true);

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
        // Connection data processing for future
      }),
      catchError(err => {
        throw err;
      })
    );
  }

  private initSessionEventHandler(): void {
    this.remoteClient.sessionListener
      .pipe(takeUntil(this.destroyed$))
      .subscribe({
        next: (event: SessionEvent): void => {
          switch (event.type) {
            case SessionEventType.STARTED:
              this.handleSessionStarted(event);
              break;
            case SessionEventType.TERMINATED:
            case SessionEventType.ERROR:
              this.handleSessionEndedOrError(event);
              break;
          }
        },
        error: (err) => this.handleSubscriptionError(err)
      });
  }

  private handleSessionStarted(event: SessionEvent): void {
    this.handleIronRDPConnectStarted();
    this.currentStatus.isInitialized = true;
  }

  private handleSessionEndedOrError(event: SessionEvent): void {
    if (document.fullscreenElement) {
      this.exitFullScreen();
    }

    this.notifyUser(event.type, event.data);
    this.disableComponentStatus();
  }

  private handleIronRDPConnectStarted(): void {
    this.loading = false;
    this.remoteClient.setVisibility(true);
    this.webSessionService.updateWebSessionIcon(this.webSessionId, WebClientVncComponent.DVL_VNC_ICON);
    this.webClientConnectionSuccess();
  }

  private notifyUser(eventType: SessionEventType, errorData: UserIronRdpError | string): void {
    this.clientError = this.getMessage(errorData);

    const icon: string = eventType === SessionEventType.TERMINATED ?
      WebClientVncComponent.DVL_WARNING_ICON :
      WebClientVncComponent.DVL_VNC_ICON;

    this.webSessionService.updateWebSessionIcon(this.webSessionId, icon);
  }

  private handleSubscriptionError(error: any): void {
    console.error('Error in session event subscription', error);
  }

  private handleIronRDPError(error: UserIronRdpError | string): void {
    this.notifyUserAboutError(error);
    this.disableComponentStatus();
  }

  private notifyUserAboutError(error: UserIronRdpError | string): void {
    this.clientError = this.getMessage(error);

    this.webSessionService.updateWebSessionIcon(this.webSessionId, WebClientVncComponent.DVL_WARNING_ICON);
  }

  private getMessage(errorData: UserIronRdpError | string): string {
    let errorKind: UserIronRdpErrorKind = UserIronRdpErrorKind.General;

    if (typeof errorData === 'string') {
      console.error(errorData);
    } else {
      errorKind = errorData.kind();
    }

    //For translation 'UnknownError'
    //For translation 'ConnectionErrorPleaseVerifyYourConnectionSettings'
    //For translation 'AccessDenied'
    //For translation 'ConnectionErrorPleaseVerifyYourConnectionSettings'
    switch (errorKind) {
      case UserIronRdpErrorKind.General:
        return 'Unknown Error';
      case UserIronRdpErrorKind.WrongPassword:
      case UserIronRdpErrorKind.LogonFailure:
        return 'Connection error: Please verify your connection settings.';
      case UserIronRdpErrorKind.AccessDenied:
        return 'Access denied';
      default:
        return 'Connection error: Please verify your connection settings.';
    }
  }
}
