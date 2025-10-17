import {
  AfterViewInit,
  Component,
  CUSTOM_ELEMENTS_SCHEMA,
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
import { ActivatedRoute } from '@angular/router';
import { IronError, SessionEvent, UserInteraction } from '@devolutions/iron-remote-desktop';
import { Backend, displayControl, kdcProxyUrl, preConnectionBlob, RdpFile } from '@devolutions/iron-remote-desktop-rdp';
import '@devolutions/iron-remote-desktop/iron-remote-desktop.js';
import { DVL_RDP_ICON, DVL_WARNING_ICON, JET_RDP_URL } from '@gateway/app.constants';
import { SessionToolbarComponent } from '@shared/components/session-toolbar/session-toolbar.component';
import { AnalyticService, ProtocolString } from '@shared/services/analytic.service';
import { WebClientBaseComponent } from '@shared/bases/base-web-client.component';
import { GatewayAlertMessageService } from '@shared/components/gateway-alert-message/gateway-alert-message.service';
import { ScreenScale } from '@shared/enums/screen-scale.enum';
import { ScreenSize } from '@shared/enums/screen-size.enum';
import { SessionEventType } from '@shared/enums/session-event-type.enum';
import { IronRDPConnectionParameters } from '@shared/interfaces/connection-params.interfaces';
import { RdpFormDataInput } from '@shared/interfaces/forms.interfaces';
import { ComponentStatus } from '@shared/models/component-status.model';
import { DesktopSize } from '@shared/models/desktop-size';
import { WebSession } from '@shared/models/web-session.model';
import { ComponentResizeObserverService } from '@shared/services/component-resize-observer.service';
import { NavigationService } from '@shared/services/navigation.service';
import { UtilsService } from '@shared/services/utils.service';
import { ExtractedUsernameDomain } from '@shared/services/utils/string.service';
import { WebClientService } from '@shared/services/web-client.service';
import { WebSessionService } from '@shared/services/web-session.service';
import { MessageService } from 'primeng/api';
import { ProgressSpinnerModule } from 'primeng/progressspinner';
import { debounceTime, EMPTY, from, noop, Observable, of, Subject, Subscription, throwError } from 'rxjs';
import { catchError, map, switchMap, takeUntil } from 'rxjs/operators';

enum UserIronRdpErrorKind {
  General = 0,
  WrongPassword = 1,
  LogonFailure = 2,
  AccessDenied = 3,
  RDCleanPath = 4,
  ProxyConnect = 5,
}

@Component({
  templateUrl: 'web-client-rdp.component.html',
  styleUrls: ['web-client-rdp.component.scss'],
  providers: [MessageService],
  standalone: true,
  imports: [SessionToolbarComponent, ProgressSpinnerModule],
  schemas: [CUSTOM_ELEMENTS_SCHEMA],
})
export class WebClientRdpComponent extends WebClientBaseComponent implements OnInit, AfterViewInit, OnDestroy {
  @Input() webSessionId: string;
  @Input() sessionsContainerElement: ElementRef;
  @Output() componentStatus: EventEmitter<ComponentStatus> = new EventEmitter<ComponentStatus>();
  @Output() sizeChange: EventEmitter<void> = new EventEmitter<void>();

  @ViewChild('sessionRdpContainer') sessionContainerElement: ElementRef;
  @ViewChild('ironRemoteDesktopElement') ironRemoteDesktopElement: ElementRef;

  backendRef = Backend;

  formData: RdpFormDataInput;
  rdpError: { kind: string; backtrace: string };
  isFullScreenMode = false;
  useUnicodeKeyboard = false;
  cursorOverrideActive = false;

  dynamicResizeSupported = false;
  dynamicResizeEnabled = false;

  rdpConfig: string | null;

  leftToolbarButtons = [
    {
      label: 'Start',
      icon: 'dvl-icon dvl-icon-windows',
      action: () => this.sendWindowsKey(),
    },
    {
      label: 'Ctrl+Alt+Del',
      icon: 'dvl-icon dvl-icon-admin',
      action: () => this.sendCtrlAltDel(),
    },
  ];

  middleToolbarButtons = [
    {
      label: 'Full Screen',
      icon: 'dvl-icon dvl-icon-fullscreen',
      action: () => this.toggleFullscreen(),
    },
    {
      label: 'Fit to Screen',
      icon: 'dvl-icon dvl-icon-minimize',
      action: () => this.scaleTo(ScreenScale.Fit),
    },
    {
      label: 'Actual Size',
      icon: 'dvl-icon dvl-icon-screen',
      action: () => this.scaleTo(ScreenScale.Real),
    },
  ];

  middleToolbarToggleButtons = [
    {
      label: 'Toggle Cursor Kind',
      icon: 'dvl-icon dvl-icon-cursor',
      action: () => this.toggleCursorKind(),
      isActive: () => !this.cursorOverrideActive,
    },
  ];

  rightToolbarButtons = [
    {
      label: 'Close Session',
      icon: 'dvl-icon dvl-icon-close',
      action: () => this.startTerminationProcess(),
    },
  ];

  checkboxes = [
    {
      label: 'Unicode Keyboard Mode',
      value: this.useUnicodeKeyboard,
      onChange: () => {
        this.useUnicodeKeyboard = !this.useUnicodeKeyboard;
        this.setKeyboardUnicodeMode(this.useUnicodeKeyboard);
      },
      enabled: () => true,
    },
    {
      label: 'Dynamic Resize',
      value: this.dynamicResizeEnabled,
      onChange: () => this.toggleDynamicResize(),
      enabled: () => this.dynamicResizeSupported,
    },
  ];

  protected removeElement = new Subject();
  private remoteClientEventListener: (event: Event) => void;
  private remoteClient: UserInteraction;

  private componentResizeObserverDisconnect?: () => void;
  private dynamicComponentResizeSubscription?: Subscription;

  constructor(
    private renderer: Renderer2,
    protected utils: UtilsService,
    private activatedRoute: ActivatedRoute,
    private navigation: NavigationService,
    protected gatewayAlertMessageService: GatewayAlertMessageService,
    private webSessionService: WebSessionService,
    private webClientService: WebClientService,
    private componentResizeService: ComponentResizeObserverService,
    protected analyticService: AnalyticService,
  ) {
    super(gatewayAlertMessageService, analyticService);
  }

  @HostListener('document:fullscreenchange')
  onFullScreenChange(): void {
    this.handleOnFullScreenEvent();
  }

  ngOnInit(): void {
    console.log('RDP init');
    this.removeWebClientGuiElement();
    this.setRdpConfig();
    // Navigate to /session route to clear query params.
    this.navigation.navigateToNewSession().then(noop);
  }

  ngAfterViewInit(): void {
    this.initiateRemoteClientListener();
  }

  ngOnDestroy(): void {
    this.removeRemoteClientListener();
    this.removeWebClientGuiElement();

    this.dynamicComponentResizeSubscription?.unsubscribe();
    this.componentResizeObserverDisconnect?.();

    super.ngOnDestroy();
  }

  private setRdpConfig(): void {
    const queryParams = this.activatedRoute.snapshot.queryParams;
    this.rdpConfig = queryParams.config ?? null;
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
    this.remoteClient.setScale(scale.valueOf());
  }

  setKeyboardUnicodeMode(useUnicode: boolean): void {
    this.remoteClient.setKeyboardUnicodeMode(useUnicode);
  }

  toggleCursorKind(): void {
    if (this.cursorOverrideActive) {
      this.remoteClient.setCursorStyleOverride(null);
    } else {
      this.remoteClient.setCursorStyleOverride('url("assets/images/crosshair.png") 7 7, default');
    }

    this.cursorOverrideActive = !this.cursorOverrideActive;
  }

  toggleDynamicResize(): void {
    const RESIZE_DEBOUNCE_TIME = 100;

    this.dynamicResizeEnabled = !this.dynamicResizeEnabled;

    if (this.dynamicResizeEnabled) {
      this.componentResizeObserverDisconnect = this.componentResizeService.observe(
        this.sessionsContainerElement.nativeElement,
      );

      this.dynamicComponentResizeSubscription = this.componentResizeService.resize$
        .pipe(debounceTime(RESIZE_DEBOUNCE_TIME))
        .subscribe(({ width, height }) => {
          if (!this.isFullScreenMode) {
            height -= WebSession.TOOLBAR_SIZE;
          }
          this.remoteClient.resize(width, height);
        });
    } else {
      this.dynamicComponentResizeSubscription?.unsubscribe();
      this.componentResizeObserverDisconnect?.();
    }
  }

  removeWebClientGuiElement(): void {
    this.removeElement.pipe(takeUntil(this.destroyed$)).subscribe({
      next: (): void => {
        if (this.ironRemoteDesktopElement?.nativeElement) {
          this.ironRemoteDesktopElement.nativeElement.remove();
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
      isInitialized: true,
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

  private toggleFullscreen(): void {
    this.isFullScreenMode = !this.isFullScreenMode;
    !document.fullscreenElement ? this.enterFullScreen() : this.exitFullScreen();

    this.scaleTo(ScreenScale.Full);
  }

  private async enterFullScreen(): Promise<void> {
    if (document.fullscreenElement) {
      return;
    }

    try {
      await this.sessionsContainerElement.nativeElement.requestFullscreen();
    } catch (err) {
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

    const sessionContainerElement = this.sessionContainerElement.nativeElement;
    const sessionToolbarElement = sessionContainerElement.querySelector('#sessionToolbar');

    if (sessionToolbarElement) {
      this.renderer.removeClass(sessionToolbarElement, 'session-toolbar-layer');
    }

    this.scaleTo(ScreenScale.Fit);
  }

  private initiateRemoteClientListener(): void {
    this.remoteClientEventListener = (event: Event) => this.readyRemoteClientEventListener(event);
    this.renderer.listen(this.ironRemoteDesktopElement.nativeElement, 'ready', this.remoteClientEventListener);
  }

  private removeRemoteClientListener(): void {
    if (this.ironRemoteDesktopElement && this.remoteClientEventListener) {
      this.renderer.destroy();
    }
  }

  private readyRemoteClientEventListener(event: Event): void {
    const customEvent = event as CustomEvent;
    this.remoteClient = customEvent.detail.irgUserInteraction;

    this.initSessionEventHandler();
    this.startConnectionProcess();
  }

  private startConnectionProcess(): void {
    const parameters = this.rdpConfig
      ? this.parseRdpConfig(this.rdpConfig)
      : this.getFormData().pipe(
        switchMap(() => this.setScreenSizeScale(this.formData.screenSize)),
        switchMap(() => this.fetchParameters(this.formData)),
      );

    parameters
      .pipe(
        takeUntil(this.destroyed$),
        switchMap((params) => this.fetchTokens(params)),
        switchMap((params) => this.webClientService.generateKdcProxyUrl(params)),
        catchError((error) => {
          console.error(error.message);
          this.handleIronRDPError(error.message);
          return EMPTY;
        }),
      )
      .subscribe((params) => {
        this.callConnect(params);
      });
  }

  private getFormData(): Observable<void> {
    return from(this.webSessionService.getWebSession(this.webSessionId)).pipe(
      map((currentWebSession) => {
        this.formData = currentWebSession.data as RdpFormDataInput;
      }),
    );
  }

  private fetchParameters(formData: RdpFormDataInput): Observable<IronRDPConnectionParameters> {
    const { hostname, password, enableDisplayControl, preConnectionBlob, kdcUrl } = formData;

    const extractedData: ExtractedUsernameDomain = this.utils.string.extractDomain(this.formData.username);

    const desktopScreenSize: DesktopSize =
      this.webClientService.getDesktopSize(this.formData) ?? this.webSessionService.getWebSessionScreenSizeSnapshot();

    const connectionParameters: IronRDPConnectionParameters = {
      username: extractedData.username,
      password,
      host: hostname,
      domain: extractedData.domain,
      gatewayAddress: this.getWebSocketUrl(),
      screenSize: desktopScreenSize,
      enableDisplayControl,
      preConnectionBlob,
      kdcUrl: this.utils.string.ensurePort(kdcUrl, ':88'),
    };
    return of(connectionParameters);
  }

  private parseRdpConfig(config: string): Observable<IronRDPConnectionParameters> {
    const rdpFile = new RdpFile();
    rdpFile.parse(atob(config));

    const host = rdpFile.getStr('full address');
    const port = rdpFile.getInt('server port');
    const username = rdpFile.getStr('username');
    const password = rdpFile.getStr('ClearTextPassword');
    const kdcProxyUrl = rdpFile.getStr('kdcproxyurl');

    const extractedUsernameDomain: ExtractedUsernameDomain = this.utils.string.extractDomain(username);

    // TODO: Parse `DesktopSize` from config.
    const screenSize: DesktopSize = this.webSessionService.getWebSessionScreenSizeSnapshot();

    const connectionParameters: IronRDPConnectionParameters = {
      username: extractedUsernameDomain.username,
      password,
      host,
      port,
      domain: extractedUsernameDomain.domain,
      gatewayAddress: this.getWebSocketUrl(),
      screenSize,
      kdcProxyUrl,
      // TODO: Parse from config.
      enableDisplayControl: true,
    };

    return of(connectionParameters);
  }

  fetchTokens(params: IronRDPConnectionParameters): Observable<IronRDPConnectionParameters> {
    return this.webClientService
      .fetchRdpToken(params)
      .pipe(switchMap((updatedParams) => this.webClientService.fetchKdcToken(updatedParams)));
  }

  private getWebSocketUrl(): string {
    const gatewayHttpAddress: URL = new URL(JET_RDP_URL, window.location.href);
    return gatewayHttpAddress.toString().replace('http', 'ws');
  }

  private setScreenSizeScale(screenSize: ScreenSize): Observable<void> {
    if (screenSize === ScreenSize.FullScreen) {
      this.scaleTo(ScreenScale.Full);
    }
    return of(undefined);
  }

  private callConnect(connectionParameters: IronRDPConnectionParameters): void {
    const configBuilder = this.remoteClient
      .configBuilder()
      .withUsername(connectionParameters.username)
      .withPassword(connectionParameters.password)
      .withDestination(connectionParameters.host)
      .withProxyAddress(connectionParameters.gatewayAddress)
      .withAuthToken(connectionParameters.token);

    if (connectionParameters.domain != null) {
      configBuilder.withServerDomain(connectionParameters.domain);
    }

    if (connectionParameters.screenSize != null) {
      configBuilder.withDesktopSize(connectionParameters.screenSize);
    }

    if (connectionParameters.enableDisplayControl) {
      configBuilder.withExtension(displayControl(true));
      this.dynamicResizeSupported = true;
    }

    if (connectionParameters.preConnectionBlob != null) {
      configBuilder.withExtension(preConnectionBlob(connectionParameters.preConnectionBlob));
    }

    if (connectionParameters.kdcProxyUrl != null) {
      configBuilder.withExtension(kdcProxyUrl(connectionParameters.kdcProxyUrl));
    }

    const config = configBuilder.build();

    from(this.remoteClient.connect(config))
      .pipe(
        // @ts-ignore // update iron-remote-gui rxjs to 7.8.1
        takeUntil(this.destroyed$),
        catchError((err) => {
          return throwError(() => err);
        }),
      )
      .subscribe();
  }

  private initSessionEventHandler(): void {
    const handler = (event: SessionEvent): void => {
      switch (event.type) {
        case SessionEventType.STARTED:
          this.handleSessionStarted(event);
          break;
        case SessionEventType.TERMINATED:
        case SessionEventType.ERROR:
          this.handleSessionEndedOrError(event);
          break;
      }
    };

    this.remoteClient.onSessionEvent(handler);
  }

  private handleSessionStarted(_event: SessionEvent): void {
    this.handleIronRDPConnectStarted();
    this.initializeStatus();
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
    void this.webSessionService.updateWebSessionIcon(this.webSessionId, DVL_RDP_ICON);
    this.webClientConnectionSuccess();
  }

  private notifyUser(event: SessionEvent, errorData: IronError | string): void {
    const eventType = event.type.valueOf();
    this.rdpError = {
      kind: this.getMessage(errorData),
      backtrace: typeof errorData !== 'string' ? errorData?.backtrace() : '',
    };

    const icon: string =
      eventType === SessionEventType.TERMINATED || SessionEventType.ERROR ? DVL_WARNING_ICON : DVL_RDP_ICON;

    void this.webSessionService.updateWebSessionIcon(this.webSessionId, icon);
  }

  private handleIronRDPError(error: IronError | string): void {
    this.notifyUserAboutError(error);
    this.disableComponentStatus();
  }

  private notifyUserAboutError(error: IronError | string): void {
    this.rdpError = {
      kind: this.getMessage(error),
      backtrace: typeof error !== 'string' ? error?.backtrace() : '',
    };

    void this.webSessionService.updateWebSessionIcon(this.webSessionId, DVL_WARNING_ICON);
  }

  private getMessage(errorData: IronError | string): string {
    let errorKind: UserIronRdpErrorKind = UserIronRdpErrorKind.General;

    if (typeof errorData === 'string') {
      return errorData;
    }
    errorKind = errorData.kind().valueOf();

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
    return 'RDP';
  }
}
