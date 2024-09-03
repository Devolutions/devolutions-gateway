import {
  AfterViewInit,
  Component,
  ElementRef,
  EventEmitter,
  HostListener,
  Input,
  OnDestroy,
  OnInit,
  Output,
  Renderer2,
  ViewChild,
} from '@angular/core';
import { MessageService } from 'primeng/api';
import {EMPTY, Observable, Subject, from, of, throwError} from 'rxjs';
import { catchError, map, switchMap, takeUntil } from 'rxjs/operators';

import { WebClientBaseComponent } from '@shared/bases/base-web-client.component';
import { GatewayAlertMessageService } from '@shared/components/gateway-alert-message/gateway-alert-message.service';
import { ScreenScale } from '@shared/enums/screen-scale.enum';
import { ScreenSize } from '@shared/enums/screen-size.enum';
import { SessionEventType } from '@shared/enums/session-event-type.enum';
import { IronVNCConnectionParameters } from '@shared/interfaces/connection-params.interfaces';
import { VncFormDataInput } from '@shared/interfaces/forms.interfaces';
import { ComponentStatus } from '@shared/models/component-status.model';
import { UtilsService } from '@shared/services/utils.service';
import { DefaultVncPort, WebClientService } from '@shared/services/web-client.service';
import { WebSessionService } from '@shared/services/web-session.service';

import { DesktopSize, SessionEvent, UserInteraction, UserIronRdpError } from '@devolutions/iron-remote-gui-vnc';
import '@devolutions/iron-remote-gui-vnc/iron-remote-gui-vnc.umd.cjs';
import { AnalyticService, ProtocolString } from '@gateway/shared/services/analytic.service';
import { ExtractedHostnamePort } from '@shared/services/utils/string.service';
import { v4 as uuidv4 } from 'uuid';
import {DVL_VNC_ICON, DVL_WARNING_ICON, JET_VNC_URL} from "@gateway/app.constants";

enum UserIronRdpErrorKind {
  General = 0,
  WrongPassword = 1,
  LogonFailure = 2,
  AccessDenied = 3,
  RDCleanPath = 4,
  ProxyConnect = 5,
}

@Component({
  templateUrl: 'web-client-vnc.component.html',
  styleUrls: ['web-client-vnc.component.scss'],
  providers: [MessageService],
})
export class WebClientVncComponent extends WebClientBaseComponent implements OnInit, AfterViewInit, OnDestroy {
  @Input() webSessionId: string;
  @Output() componentStatus: EventEmitter<ComponentStatus> = new EventEmitter<ComponentStatus>();
  @Output() sizeChange: EventEmitter<void> = new EventEmitter<void>();

  @ViewChild('sessionVncContainer') sessionContainerElement: ElementRef;
  @ViewChild('ironGuiElementVnc') ironGuiElement: ElementRef;

  screenScale = ScreenScale;
  currentStatus: ComponentStatus;
  inputFormData: VncFormDataInput;
  clientError: { kind: string; backtrace: string };
  isFullScreenMode = false;
  showToolbarDiv = true;
  loading = true;

  protected removeElement: Subject<any> = new Subject();
  private remoteClient: UserInteraction;
  private remoteClientEventListener: (event: Event) => void;

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
    if (!this.currentStatus.isInitialized) {
      return;
    }
    this.currentStatus.isInitialized = false;
    // shutdowns the session, not the server. Jan 2024 KAH.
    this.remoteClient.shutdown();
  }

  scaleTo(scale: ScreenScale): void {
    if (scale === ScreenScale.Full) {
      this.toggleFullscreen();
    } else {
      this.remoteClient.setScale(scale.valueOf());
    }
  }

  removeWebClientGuiElement(): void {
    this.removeElement.pipe(takeUntil(this.destroyed$)).subscribe({
      next: (): void => {
        if (this.ironGuiElement && this.ironGuiElement.nativeElement) {
          this.ironGuiElement.nativeElement.remove();
        }
      },
      error: (err): void => {
        console.error('Error while removing element:', err);
      },
    });
  }

  private initializeStatus(): void {
    this.currentStatus = {
      id: this.webSessionId,
      isInitialized: false,
      isDisabled: false,
      isDisabledByUser: false,
    };
  }

  private disableComponentStatus(): void {
    this.currentStatus.isDisabled = true;
    this.componentStatus.emit(this.currentStatus);
  }

  private handleOnFullScreenEvent(): void {
    if (!document.fullscreenElement) {
      this.handleExitFullScreenEvent();
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

  private async enterFullScreen(): Promise<void> {
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
      document.exitFullscreen().catch((err) => {
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

    this.remoteClient.setScale(ScreenScale.Fit.valueOf());
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
    this.getFormData()
      .pipe(
        takeUntil(this.destroyed$),
        switchMap(() => this.setScreenSizeScale(this.inputFormData.screenSize)),
        switchMap(() => this.fetchParameters(this.inputFormData)),
        switchMap((params) => this.fetchTokens(params)),
        catchError((error) => {
          console.error(error.message);
          this.handleIronRDPError(error.message);
          return EMPTY;
        }),
      )
      .subscribe((params) => {
        this.callConnect(params)
      });
  }

  private getFormData(): Observable<void> {
    return from(this.webSessionService.getWebSession(this.webSessionId)).pipe(
      map((currentWebSession) => (this.inputFormData = currentWebSession.data)),
    );
  }

  private fetchParameters(formData: VncFormDataInput): Observable<IronVNCConnectionParameters> {
    const { hostname, username, password } = formData;
    const extractedData: ExtractedHostnamePort = this.utils.string.extractHostnameAndPort(hostname, DefaultVncPort);

    const sessionId: string = uuidv4();
    const gatewayHttpAddress: URL = new URL(JET_VNC_URL + `/${sessionId}`, window.location.href);
    const gatewayAddress: string = gatewayHttpAddress.toString().replace('http', 'ws');

    const desktopScreenSize: DesktopSize =
      this.webClientService.getDesktopSize(this.inputFormData) ??
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
      sessionId: sessionId,
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

  private callConnect(connectionParameters: IronVNCConnectionParameters): void {
    this.remoteClient.setKeyboardUnicodeMode(true);
    this.remoteClient
      .connect(
        connectionParameters.username,
        connectionParameters.password,
        connectionParameters.host,
        connectionParameters.gatewayAddress,
        connectionParameters.domain,
        connectionParameters.token,
        connectionParameters.screenSize,
        connectionParameters.preConnectionBlob,
        connectionParameters.kdcProxyUrl,
      )
      .pipe(
        // @ts-ignore // update iron-remote-gui rxjs to 7.8.1
        takeUntil(this.destroyed$),
        catchError((err) => {
          return throwError(() => err);
        }),
      ).subscribe();
  }

  private initSessionEventHandler(): void {
    this.remoteClient.sessionListener.subscribe({
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
      error: (err) => this.handleSubscriptionError(err),
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

    this.notifyUser(event, event.data);
    this.disableComponentStatus();
    super.webClientConnectionClosed();
  }

  private handleIronRDPConnectStarted(): void {
    this.loading = false;
    this.remoteClient.setVisibility(true);
    void this.webSessionService.updateWebSessionIcon(this.webSessionId, DVL_VNC_ICON);
    this.webClientConnectionSuccess();
  }

  private notifyUser(event: SessionEvent, errorData: UserIronRdpError | string): void {
    const eventType = event.type.valueOf() ;
    this.clientError = {
      kind: this.getMessage(errorData),
      backtrace: typeof errorData !== 'string' ? errorData?.backtrace() : '',
    };

    const icon: string =
      eventType === SessionEventType.TERMINATED || SessionEventType.ERROR
        ? DVL_WARNING_ICON
        : DVL_VNC_ICON;

    void this.webSessionService.updateWebSessionIcon(this.webSessionId, icon);
  }

  private handleSubscriptionError(error: any): void {
    console.error('Error in session event subscription', error);
  }

  private handleIronRDPError(error: UserIronRdpError | string): void {
    this.notifyUserAboutError(error);
    this.disableComponentStatus();
  }

  private notifyUserAboutError(error: UserIronRdpError | string): void {
    this.clientError = {
      kind: this.getMessage(error),
      backtrace: typeof error !== 'string' ? error?.backtrace() : '',
    };

    void this.webSessionService.updateWebSessionIcon(this.webSessionId, DVL_WARNING_ICON);
  }

  private getMessage(errorData: UserIronRdpError | string): string {
    let errorKind: UserIronRdpErrorKind = UserIronRdpErrorKind.General;

    if (typeof errorData === 'string') {
      return errorData;
    } else {
      errorKind = errorData.kind().valueOf();
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

  protected getProtocol(): ProtocolString {
    return 'VNC';
  }
}
