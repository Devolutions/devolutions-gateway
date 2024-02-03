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
import {from, Observable, Subject} from "rxjs";
import {catchError, map, mergeMap, switchMap, takeUntil, tap} from 'rxjs/operators';
import {MessageService} from "primeng/api";

import { WebClientBaseComponent } from "@shared/bases/base-web-client.component";
import {IronRDPConnectionParameters} from "@shared/services/web-client.service";
import {GatewayAlertMessageService} from "@shared/components/gateway-alert-message/gateway-alert-message.service";
import {ComponentStatus} from "@shared/models/component-status.model";
import {WebSessionService} from "@shared/services/web-session.service";
import {UtilsService} from "@shared/services/utils.service";
import {WebClientService} from "@shared/services/web-client.service";

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

  static DVL_RDP_ICON: string = 'dvl-icon-entry-session-rdp';
  static DVL_WARNING_ICON: string = 'dvl-icon-warning';
  static JET_RDP_URL: string = '/jet/rdp';
  static JET_KDC_PROXY_URL: string = '/jet/KdcProxy';

  screenScale = ScreenScale;
  currentStatus: ComponentStatus;
  inputFormData: any;
  rdpError: string;
  isFullScreenMode: boolean = false;
  showToolbarDiv: boolean = true;
  loading: boolean = true;

  protected removeElement: Subject<any> = new Subject();
  private remoteClientEventListener: (event: Event) => void;
  private remoteClient: UserInteraction;

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

  sendTerminateSessionCmd(): void {
    // shutdowns the session, not the server
    this.remoteClient.shutdown();
    this.currentStatus.isDisabledByUser = true;
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
    !document.fullscreenElement ? this.enterFullScreenMode() : document.exitFullscreen();
  }

  private async enterFullScreenMode(): Promise<void>  {
    if (document.fullscreenElement) {
      return;
    }
    try {
      const sessionContainerElement = this.sessionContainerElement.nativeElement;
      await sessionContainerElement.requestFullscreen();

      // using .Full screen scale causes scrollbars, Fit works better in this case. KAH Jan 2024
      this.remoteClient.setScale(ScreenScale.Fit);

    } catch (err: any) {
      this.isFullScreenMode = false;
      console.error(`Error attempting to enable fullscreen mode: ${err.message} (${err.name})`);
    }
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
    this.remoteClientEventListener = (event: Event) => this.readyRemoteClientEventListener(event);
    this.renderer.listen(this.ironGuiElement.nativeElement, 'ready', this.remoteClientEventListener);
  }

  private removeRemoteClientListener(): void {
    if (this.ironGuiElement && this.remoteClientEventListener) {
      this.renderer.destroy(); // Make sure to destroy the listener properly
    }
  }

  private readyRemoteClientEventListener(event: Event): void {
    const customEvent = event as CustomEvent;
    this.remoteClient = customEvent.detail.irgUserInteraction;

    this.initSessionEventHandler();
    this.startConnectionProcess();
  }

  private startConnectionProcess(): void {
    this.getFormData().pipe(
      takeUntil(this.destroyed$),
      switchMap((connectionParameters)=> this.webClientService.fetchRdpToken(connectionParameters)),
      switchMap((connectionParameters)=> this.webClientService.fetchKdcToken(connectionParameters)),
      switchMap((connectionParameters)=> this.webClientService.generateKdcProxyUrl(connectionParameters)),
      mergeMap(connectionParameters => this.callConnect(connectionParameters))
    ).subscribe(
      () => {},
      (error) => {
          console.error(error.message);
          this.handleIronRDPError(error.message);
      });
  }

  private getFormData(): Observable<IronRDPConnectionParameters> {
    return from(this.webSessionService.getWebSession(this.tabIndex)).pipe(
      tap(currentWebSession => this.inputFormData = currentWebSession.data),
      map(() => {
        const { hostname, username, password, desktopSize, preConnectionBlob, kdcUrl } = this.inputFormData;
        const extractedData = this.utils.string.extractDomain(username);
        const gatewayHttpAddress: URL = new URL(WebClientRdpComponent.JET_RDP_URL, window.location.href);
        const websocketUrl: string = gatewayHttpAddress.toString().replace("http", "ws");

        const connectionParameters: IronRDPConnectionParameters = {
          username: extractedData.username,
          password: password,
          host: hostname,
          domain: extractedData.domain,
          gatewayAddress: websocketUrl,
          screenSize: desktopSize,
          preConnectionBlob: preConnectionBlob,
          kdcUrl: this.utils.string.ensurePort(kdcUrl, ':88')
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
    this.currentStatus.isDisabled = true;
    this.notifyUser(event.type, event.data);
    this.componentStatus.emit(this.currentStatus);
  }

  private handleIronRDPConnectStarted(): void {
    this.loading = false;
    this.remoteClient.setVisibility(true);
    this.webSessionService.updateWebSessionIcon(this.tabIndex, WebClientRdpComponent.DVL_RDP_ICON);
    this.webClientConnectionSuccess();
  }

  private notifyUser(eventType: SessionEventType, errorData: UserIronRdpError | string): void {
    this.tabIndex = this.currentStatus.tabIndex;
    this.rdpError = typeof errorData === 'string' ? errorData : this.getMessage(errorData.kind());

    const icon = eventType === SessionEventType.TERMINATED ? WebClientRdpComponent.DVL_WARNING_ICON : WebClientRdpComponent.DVL_RDP_ICON;
    this.webSessionService.updateWebSessionIcon(this.tabIndex, icon);
  }

  private handleSubscriptionError(error: any): void {
    console.error('Error in session event subscription', error);
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
    this.webSessionService.updateWebSessionIcon(this.tabIndex, WebClientRdpComponent.DVL_WARNING_ICON);
  }

  private getMessage(errorKind: UserIronRdpErrorKind): string {
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
