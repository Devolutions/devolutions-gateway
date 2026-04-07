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
import { IronError, SessionTerminationInfo } from '@devolutions/iron-remote-desktop';
import { DesktopWebClientBaseComponent } from '@shared/bases/desktop-web-client-base.component';
import {
  ScreenMode,
  ToolbarFeatures,
  WheelSpeedControl,
} from '@shared/components/floating-session-toolbar/floating-session-toolbar.component';
import { GatewayAlertMessageService } from '@shared/components/gateway-alert-message/gateway-alert-message.service';
import { ScreenScale } from '@shared/enums/screen-scale.enum';
import { ScreenSize } from '@shared/enums/screen-size.enum';
import { IronVNCConnectionParameters } from '@shared/interfaces/connection-params.interfaces';
import { VncFormDataInput } from '@shared/interfaces/forms.interfaces';
import { ComponentStatus } from '@shared/models/component-status.model';
import { DesktopSize } from '@shared/models/desktop-size';
import { UtilsService } from '@shared/services/utils.service';
import { DefaultVncPort, WebClientService } from '@shared/services/web-client.service';
import { WebSessionService } from '@shared/services/web-session.service';
import type { ToastMessageOptions } from 'primeng/api';
import { MessageService } from 'primeng/api';
import { debounceTime, EMPTY, from, Observable, of, Subject, Subscription } from 'rxjs';
import { catchError, map, switchMap, takeUntil } from 'rxjs/operators';
import '@devolutions/iron-remote-desktop/iron-remote-desktop.js';
import {
  Backend,
  dynamicResizingSupportedCallback,
  enableCursor,
  enabledEncodings,
  enableExtendedClipboard,
  jpegQualityLevel,
  pixelFormat,
  ultraVirtualDisplay,
  wheelSpeedFactor,
} from '@devolutions/iron-remote-desktop-vnc';
import { DVL_VNC_ICON, DVL_WARNING_ICON, JET_VNC_URL } from '@gateway/app.constants';
import { AnalyticService, ProtocolString } from '@gateway/shared/services/analytic.service';
import { Encoding } from '@shared/enums/encoding.enum';
import { ComponentResizeObserverService } from '@shared/services/component-resize-observer.service';
import { ExtractedHostnamePort } from '@shared/services/utils/string.service';
import { v4 as uuidv4 } from 'uuid';

enum UserIronRdpErrorKind {
  General = 0,
  WrongPassword = 1,
  LogonFailure = 2,
  AccessDenied = 3,
  RDCleanPath = 4,
  ProxyConnect = 5,
}

@Component({
  standalone: false,
  templateUrl: 'web-client-vnc.component.html',
  styleUrls: ['web-client-vnc.component.scss'],
  providers: [MessageService],
})
export class WebClientVncComponent extends DesktopWebClientBaseComponent implements OnInit, AfterViewInit, OnDestroy {
  @Input() webSessionId: string;
  @Input() sessionsContainerElement: ElementRef;
  @Output() componentStatus: EventEmitter<ComponentStatus> = new EventEmitter<ComponentStatus>();
  @Output() sizeChange: EventEmitter<void> = new EventEmitter<void>();

  @ViewChild('sessionVncContainer') sessionContainerElement: ElementRef;
  @ViewChild('ironRemoteDesktopElement') ironRemoteDesktopElement: ElementRef;

  backendRef = Backend;

  formData: VncFormDataInput;
  sessionTerminationMessage: ToastMessageOptions;
  isFullScreenMode = false;
  cursorOverrideActive = false;
  wheelSpeed = 1;

  dynamicResizeSupported = false;
  dynamicResizeEnabled = false;

  readonly toolbarFeatures: ToolbarFeatures = {
    windowsKey: true,
    ctrlAltDel: true,
    screenMode: true,
    dynamicResize: true,
    cursorCrosshair: true,
    wheelSpeed: true,
  };

  readonly wheelSpeedControl: WheelSpeedControl = {
    label: 'Wheel speed',
    min: 0.1,
    max: 3,
    step: 0.1,
  };

  protected removeElement: Subject<unknown> = new Subject();
  private remoteClientEventListener: (event: Event) => void;

  private componentResizeObserverDisconnect?: () => void;
  private dynamicComponentResizeSubscription?: Subscription;

  constructor(
    private renderer: Renderer2,
    protected utils: UtilsService,
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
    this.removeWebClientGuiElement();
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

  setWheelSpeedFactor(factor: number): void {
    this.wheelSpeed = factor;
    if (this.remoteClient) {
      this.remoteClient.invokeExtension(wheelSpeedFactor(factor));
    }
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
          // The floating toolbar is an overlay and does not consume layout height.
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

  onScreenModeChange(mode: ScreenMode): void {
    switch (mode) {
      case 'fullscreen':
        this.toggleFullscreen();
        break;
      case 'fit':
        this.scaleTo(ScreenScale.Fit);
        break;
      case 'minimize':
        this.scaleTo(ScreenScale.Real);
        break;
    }
  }

  onDynamicResizeChange(enabled: boolean): void {
    if (enabled !== this.dynamicResizeEnabled) {
      this.toggleDynamicResize();
    }
  }

  onCursorCrosshairChange(enabled: boolean): void {
    if (enabled !== this.cursorOverrideActive) {
      this.toggleCursorKind();
    }
  }

  onWheelSpeedChange(factor: number): void {
    this.setWheelSpeedFactor(factor);
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
      const sessionsContainerElement = this.sessionsContainerElement.nativeElement;
      await sessionsContainerElement.requestFullscreen();
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
    // The floating toolbar overlays the session, so no DOM toolbar adjustments are needed here.
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

    this.remoteClient.setEnableAutoClipboard(this.isAutoClipboardMode(this.formData?.autoClipboard));

    // Register callbacks for events.
    this.remoteClient.onWarningCallback((data: string) => {
      this.webClientWarning(data);
    });
    this.remoteClient.onClipboardRemoteUpdateCallback(() => {
      this.saveRemoteClipboardButtonEnabled = true;
    });

    this.startConnectionProcess();
  }

  private startConnectionProcess(): void {
    this.getFormData()
      .pipe(
        takeUntil(this.destroyed$),
        switchMap(() => this.setScreenSizeScale(this.formData.screenSize)),
        switchMap(() => this.fetchParameters(this.formData)),
        switchMap((params) => this.fetchTokens(params)),
        catchError((error) => {
          this.handleError(error.message);
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
        // It's not possibe to infer the type of currentWebSession.data, we case it on the fly
        this.formData = currentWebSession.data as unknown as VncFormDataInput;
        this.wheelSpeed = this.formData.wheelSpeedFactor ?? 1;
        this.setupClipboardHandling(this.formData.autoClipboard);
      }),
    );
  }

  private fetchParameters(formData: VncFormDataInput): Observable<IronVNCConnectionParameters> {
    const {
      hostname,
      username,
      password,
      enableCursor,
      enableExtendedClipboard,
      enabledEncodings,
      colorFormat,
      ultraVirtualDisplay,
      jpegEnabled,
      jpegQualityLevel,
      wheelSpeedFactor = 1,
    } = formData;
    const extractedData: ExtractedHostnamePort = this.utils.string.extractHostnameAndPort(hostname, DefaultVncPort);

    const sessionId: string = uuidv4();
    const gatewayHttpAddress: URL = new URL(JET_VNC_URL + `/${sessionId}`, window.location.href);
    const gatewayAddress: string = gatewayHttpAddress.toString().replace('http', 'ws');

    const desktopScreenSize: DesktopSize =
      this.webClientService.getDesktopSize(this.formData) ?? this.webSessionService.getWebSessionScreenSizeSnapshot();

    const connectionParameters: IronVNCConnectionParameters = {
      username,
      password,
      host: extractedData.hostname,
      port: extractedData.port,
      gatewayAddress,
      screenSize: desktopScreenSize,
      sessionId,
      enabledEncodings: enabledEncodings.join(','),
      colorFormat,
      jpegQualityLevel: jpegEnabled ? jpegQualityLevel : undefined,
      enableCursor,
      enableExtendedClipboard: enableExtendedClipboard ?? false,
      ultraVirtualDisplay,
      wheelSpeedFactor,
    };
    return of(connectionParameters);
  }

  fetchTokens(params: IronVNCConnectionParameters): Observable<IronVNCConnectionParameters> {
    return this.webClientService.fetchVncToken(params);
  }

  private setScreenSizeScale(screenSize: ScreenSize): Observable<void> {
    if (screenSize === ScreenSize.FullScreen) {
      this.scaleTo(ScreenScale.Full);
    }
    return of(undefined);
  }

  private callConnect(connectionParameters: IronVNCConnectionParameters): void {
    const configBuilder = this.remoteClient
      .configBuilder()
      .withDestination(connectionParameters.host)
      .withProxyAddress(connectionParameters.gatewayAddress)
      .withAuthToken(connectionParameters.token)
      .withExtension(
        dynamicResizingSupportedCallback(() => {
          this.dynamicResizeSupported = true;
        }),
      )
      .withExtension(enableCursor(connectionParameters.enableCursor))
      .withExtension(ultraVirtualDisplay(connectionParameters.ultraVirtualDisplay))
      .withExtension(enableExtendedClipboard(connectionParameters.enableExtendedClipboard));

    if (connectionParameters.username != null) {
      configBuilder.withUsername(connectionParameters.username);
    }

    if (connectionParameters.password != null) {
      configBuilder.withPassword(connectionParameters.password);
    }

    if (connectionParameters.screenSize != null) {
      configBuilder.withDesktopSize(connectionParameters.screenSize);
    }

    if (connectionParameters.enabledEncodings !== '') {
      configBuilder.withExtension(enabledEncodings(connectionParameters.enabledEncodings));
    } else {
      configBuilder.withExtension(enabledEncodings(Encoding.getAllEncodings().join(',')));
    }

    if (connectionParameters.colorFormat) {
      configBuilder.withExtension(pixelFormat(connectionParameters.colorFormat));
    }

    if (connectionParameters.jpegQualityLevel != null) {
      configBuilder.withExtension(jpegQualityLevel(connectionParameters.jpegQualityLevel));
    }

    configBuilder.withExtension(wheelSpeedFactor(connectionParameters.wheelSpeedFactor));

    const config = configBuilder.build();

    this.setKeyboardUnicodeMode(true);

    from(this.remoteClient.connect(config))
      .pipe(
        takeUntil(this.destroyed$),
        switchMap((newSessionInfo) => {
          this.handleSessionStarted();
          return from(newSessionInfo.run());
        }),
      )
      .subscribe({
        next: (sessionTerminationInfo) => this.handleSessionTerminatedGracefully(sessionTerminationInfo),
        error: (err) => this.handleSessionTerminatedWithError(err),
      });
  }

  private handleSessionStarted(): void {
    this.loading = false;
    this.remoteClient.setVisibility(true);
    void this.webSessionService.updateWebSessionIcon(this.webSessionId, DVL_VNC_ICON);
    this.webClientConnectionSuccess();
    this.initializeStatus();
  }

  private handleSessionTerminatedGracefully(sessionTerminationInfo: SessionTerminationInfo): void {
    this.sessionTerminationMessage = {
      summary: 'Session terminated gracefully',
      detail: sessionTerminationInfo.reason(),
      severity: 'success',
    };

    this.handleSessionTerminated();
  }

  private handleSessionTerminatedWithError(error: unknown): void {
    if (this.isIronError(error)) {
      this.sessionTerminationMessage = {
        summary: this.getIronErrorMessageTitle(error),
        detail: error.backtrace(),
        severity: 'error',
      };
    } else {
      this.sessionTerminationMessage = {
        summary: 'Unexpected error occurred',
        detail: `${error}`,
        severity: 'error',
      };
    }

    void this.webSessionService.updateWebSessionIcon(this.webSessionId, DVL_WARNING_ICON);

    this.handleSessionTerminated();
  }

  private handleSessionTerminated(): void {
    if (document.fullscreenElement) {
      this.exitFullScreen();
    }

    this.disableComponentStatus();
    super.webClientConnectionClosed();
  }

  private handleError(error: string): void {
    this.sessionTerminationMessage = {
      summary: 'Unexpected error occurred',
      detail: error,
      severity: 'error',
    };
    this.disableComponentStatus();
  }

  private getIronErrorMessageTitle(error: IronError): string {
    const errorKind: UserIronRdpErrorKind = error.kind().valueOf();

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
