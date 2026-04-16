import { Component, ElementRef, OnDestroy, OnInit, Renderer2, ViewChild } from '@angular/core';
import { DesktopWebClientBaseComponent } from '@shared/bases/desktop-web-client-base.component';
import { GatewayAlertMessageService } from '@shared/components/gateway-alert-message/gateway-alert-message.service';
import { ScreenScale } from '@shared/enums/screen-scale.enum';
import { ScreenSize } from '@shared/enums/screen-size.enum';
import { IronVNCConnectionParameters } from '@shared/interfaces/connection-params.interfaces';
import { VncFormDataInput } from '@shared/interfaces/forms.interfaces';
import { DesktopSize } from '@shared/models/desktop-size';
import { UtilsService } from '@shared/services/utils.service';
import { DefaultVncPort, WebClientService } from '@shared/services/web-client.service';
import { WebSessionService } from '@shared/services/web-session.service';
import { MessageService } from 'primeng/api';
import { debounceTime, EMPTY, from, Observable, of, Subscription } from 'rxjs';
import { catchError, map, switchMap, takeUntil, tap } from 'rxjs/operators';
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
import { DVL_VNC_ICON, JET_VNC_URL } from '@gateway/app.constants';
import { AnalyticService, ProtocolString } from '@gateway/shared/services/analytic.service';
import { WheelSpeedControl } from '@shared/components/floating-session-toolbar/models/floating-session-toolbar-config.model';
import { Encoding } from '@shared/enums/encoding.enum';
import { ComponentResizeObserverService } from '@shared/services/component-resize-observer.service';
import { ExtractedHostnamePort } from '@shared/services/utils/string.service';
import { v4 as uuidv4 } from 'uuid';

@Component({
  standalone: false,
  templateUrl: 'web-client-vnc.component.html',
  styleUrls: ['web-client-vnc.component.scss'],
  providers: [MessageService],
})
export class WebClientVncComponent
  extends DesktopWebClientBaseComponent<VncFormDataInput>
  implements OnInit, OnDestroy
{
  @ViewChild('sessionVncContainer') sessionContainerElement: ElementRef;

  backendRef = Backend;

  // ── Floating toolbar state ─────────────────────────────────────────────────
  dynamicResizeSupported = false;
  dynamicResizeEnabled = false;
  // sessionInfo / sessionInfoUrl / sessionInfoUsername / refreshSessionInfo() inherited from WebClientBaseComponent

  wheelSpeed = 1;
  readonly wheelSpeedControl: WheelSpeedControl = {
    label: 'Wheel speed',
    min: 0.1,
    max: 3,
    step: 0.1,
  };
  // ──

  private componentResizeObserverDisconnect?: () => void;
  private dynamicComponentResizeSubscription?: Subscription;

  constructor(
    protected renderer: Renderer2,
    protected utils: UtilsService,
    protected gatewayAlertMessageService: GatewayAlertMessageService,
    protected webSessionService: WebSessionService,
    private webClientService: WebClientService,
    private componentResizeService: ComponentResizeObserverService,
    protected analyticService: AnalyticService,
  ) {
    super(renderer, webSessionService, gatewayAlertMessageService, analyticService);
  }

  ngOnInit(): void {
    this.webSessionIcon = DVL_VNC_ICON;
    this.refreshSessionInfo();

    super.ngOnInit();
  }

  ngOnDestroy(): void {
    this.dynamicComponentResizeSubscription?.unsubscribe();
    this.componentResizeObserverDisconnect?.();
    super.ngOnDestroy();
  }

  // ── Floating toolbar handlers ─────────────────────────────────────────────
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

  private setWheelSpeedFactor(factor: number): void {
    this.wheelSpeed = factor;
    if (this.remoteClient) {
      this.remoteClient.invokeExtension(wheelSpeedFactor(factor));
    }
  }

  private toggleDynamicResize(): void {
    const RESIZE_DEBOUNCE_TIME = 100;

    this.dynamicResizeEnabled = !this.dynamicResizeEnabled;

    if (this.dynamicResizeEnabled) {
      this.componentResizeObserverDisconnect = this.componentResizeService.observe(
        this.sessionsContainerElement.nativeElement,
      );

      this.dynamicComponentResizeSubscription = this.componentResizeService.resize$
        .pipe(debounceTime(RESIZE_DEBOUNCE_TIME))
        .subscribe(({ width, height }) => {
          this.remoteClient.resize(width, height);
        });
    } else {
      this.dynamicComponentResizeSubscription?.unsubscribe();
      this.componentResizeObserverDisconnect?.();
    }
  }

  protected handleExitFullScreenEvent(): void {
    this.isFullScreenMode = false;

    const sessionContainerElement = this.sessionContainerElement.nativeElement;
    const sessionToolbarElement = sessionContainerElement.querySelector('#sessionToolbar');

    if (sessionToolbarElement) {
      this.renderer.removeClass(sessionToolbarElement, 'session-toolbar-layer');
    }

    this.scaleTo(ScreenScale.Fit);
  }
  // ──

  protected startConnectionProcess(): void {
    this.getFormData()
      .pipe(
        takeUntil(this.destroyed$),
        tap(() => this.setupClipboardHandling(this.formData.autoClipboard)),
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
        this.sessionInfoUsername = this.formData.username ?? null;
        this.refreshSessionInfo();
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
    this.sessionInfoUrl = this.toUserFacingUrl(gatewayAddress);
    this.sessionInfoUsername = username ?? null;
    this.refreshSessionInfo();

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

  private fetchTokens(params: IronVNCConnectionParameters): Observable<IronVNCConnectionParameters> {
    return this.webClientService.fetchVncToken(params);
  }

  private setScreenSizeScale(screenSize: ScreenSize): Observable<void> {
    if (screenSize === ScreenSize.FullScreen) {
      this.scaleTo(ScreenScale.Full);
    }
    return of(undefined);
  }

  protected callConnect(connectionParameters: IronVNCConnectionParameters): void {
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

  protected getProtocol(): ProtocolString {
    return 'VNC';
  }
}
