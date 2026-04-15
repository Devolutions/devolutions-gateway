import { AfterViewInit, Component, ElementRef, OnDestroy, OnInit, Renderer2, ViewChild } from '@angular/core';
import { Backend, displayControl, kdcProxyUrl, preConnectionBlob, RdpFile } from '@devolutions/iron-remote-desktop-rdp';
import { DesktopWebClientBaseComponent } from '@shared/bases/desktop-web-client-base.component';
import { GatewayAlertMessageService } from '@shared/components/gateway-alert-message/gateway-alert-message.service';
import { ScreenScale } from '@shared/enums/screen-scale.enum';
import { ScreenSize } from '@shared/enums/screen-size.enum';
import { IronRDPConnectionParameters } from '@shared/interfaces/connection-params.interfaces';
import { RdpFormDataInput } from '@shared/interfaces/forms.interfaces';
import { DesktopSize } from '@shared/models/desktop-size';
import { ExtractedUsernameDomain } from '@shared/services/utils/string.service';
import { UtilsService } from '@shared/services/utils.service';
import { WebClientService } from '@shared/services/web-client.service';
import { WebSessionService } from '@shared/services/web-session.service';
import { MessageService } from 'primeng/api';
import { debounceTime, EMPTY, from, noop, Observable, of, Subscription, throwError } from 'rxjs';
import { catchError, map, switchMap, takeUntil, tap } from 'rxjs/operators';
import '@devolutions/iron-remote-desktop/iron-remote-desktop.js';
import { ActivatedRoute } from '@angular/router';
import { SessionTerminationInfo } from '@devolutions/iron-remote-desktop';
import { DVL_RDP_ICON, JET_RDP_URL } from '@gateway/app.constants';
import { AnalyticService, ProtocolString } from '@gateway/shared/services/analytic.service';
import { WebSession } from '@shared/models/web-session.model';
import { ComponentResizeObserverService } from '@shared/services/component-resize-observer.service';
import { NavigationService } from '@shared/services/navigation.service';

@Component({
  standalone: false,
  templateUrl: 'web-client-rdp.component.html',
  styleUrls: ['web-client-rdp.component.scss'],
  providers: [MessageService],
})
export class WebClientRdpComponent
  extends DesktopWebClientBaseComponent<RdpFormDataInput>
  implements OnInit, AfterViewInit, OnDestroy
{
  @ViewChild('sessionRdpContainer') sessionContainerElement: ElementRef;

  backendRef = Backend;
  useUnicodeKeyboard = false;

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
      inputId: 'unicodeKeyboardMode',
      label: 'Unicode Keyboard Mode',
      value: this.useUnicodeKeyboard,
      onChange: () => {
        this.useUnicodeKeyboard = !this.useUnicodeKeyboard;
        this.setKeyboardUnicodeMode(this.useUnicodeKeyboard);
      },
      enabled: () => true,
    },
    {
      inputId: 'dynamicResize',
      label: 'Dynamic Resize',
      value: this.dynamicResizeEnabled,
      onChange: () => this.toggleDynamicResize(),
      enabled: () => this.dynamicResizeSupported,
    },
  ];

  private componentResizeObserverDisconnect?: () => void;
  private dynamicComponentResizeSubscription?: Subscription;

  constructor(
    protected renderer: Renderer2,
    protected utils: UtilsService,
    private activatedRoute: ActivatedRoute,
    private navigation: NavigationService,
    protected gatewayAlertMessageService: GatewayAlertMessageService,
    protected webSessionService: WebSessionService,
    private webClientService: WebClientService,
    private componentResizeService: ComponentResizeObserverService,
    protected analyticService: AnalyticService,
  ) {
    super(renderer, webSessionService, gatewayAlertMessageService, analyticService);
  }

  ngOnInit(): void {
    this.webSessionIcon = DVL_RDP_ICON;
    this.setRdpConfig();
    // Navigate to /session route to clear query params.
    this.navigation.navigateToNewSession().then(noop);

    super.ngOnInit();
  }

  ngOnDestroy(): void {
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

  protected handleExitFullScreenEvent(): void {
    this.isFullScreenMode = false;

    const sessionContainerElement = this.sessionContainerElement.nativeElement;
    const sessionToolbarElement = sessionContainerElement.querySelector('#sessionToolbar');

    if (sessionToolbarElement) {
      this.renderer.removeClass(sessionToolbarElement, 'session-toolbar-layer');
    }

    this.scaleTo(ScreenScale.Fit);
  }

  protected startConnectionProcess(): void {
    let parameters: Observable<IronRDPConnectionParameters>;
    if (this.rdpConfig) {
      this.setupClipboardHandling();
      parameters = this.parseRdpConfig(this.rdpConfig);
    } else {
      parameters = this.getFormData().pipe(
        tap(() => this.setupClipboardHandling(this.formData.autoClipboard)),
        switchMap(() => this.setScreenSizeScale(this.formData.screenSize)),
        switchMap(() => this.fetchParameters(this.formData)),
      );
    }

    parameters
      .pipe(
        takeUntil(this.destroyed$),
        switchMap((params) => this.fetchTokens(params)),
        switchMap((params) => this.webClientService.generateKdcProxyUrl(params)),
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
        this.formData = currentWebSession.data as RdpFormDataInput;
      }),
    );
  }

  private fetchParameters(formData: RdpFormDataInput): Observable<IronRDPConnectionParameters> {
    const { hostname, password, enableDisplayControl, preConnectionBlob, kdcUrl } = formData;

    const extractedData: ExtractedUsernameDomain = this.utils.string.extractDomain(this.formData.username);
    const gatewayAddress = this.getGatewayWebSocketUrl(JET_RDP_URL);

    const desktopScreenSize: DesktopSize =
      this.webClientService.getDesktopSize(this.formData) ?? this.webSessionService.getWebSessionScreenSizeSnapshot();

    const connectionParameters: IronRDPConnectionParameters = {
      username: extractedData.username,
      password,
      host: hostname,
      domain: extractedData.domain,
      gatewayAddress: gatewayAddress,
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

    if (host === undefined) {
      return throwError(() => new Error('Invalid configuration: `host` is not provided'));
    }

    if (username === undefined) {
      return throwError(() => new Error('Invalid configuration: `username` is not provided'));
    }

    if (password === undefined) {
      return throwError(() => new Error('Invalid configuration: `ClearTextPassword` is not provided'));
    }

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

  private fetchTokens(params: IronRDPConnectionParameters): Observable<IronRDPConnectionParameters> {
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

  protected callConnect(connectionParameters: IronRDPConnectionParameters): void {
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

    // Guard against synchronous throws from the underlying WASM library before
    // the promise is even returned (observed in some auth-failure edge cases).
    let connectPromise: Promise<unknown>;
    try {
      connectPromise = this.remoteClient.connect(config);
    } catch (syncErr) {
      this.handleSessionTerminatedWithError(syncErr);
      return;
    }

    from(connectPromise)
      .pipe(
        takeUntil(this.destroyed$),
        switchMap((newSessionInfo) => {
          this.handleSessionStarted();
          return from((newSessionInfo as { run(): Promise<unknown> }).run());
        }),
      )
      .subscribe({
        next: (sessionTerminationInfo) =>
          this.handleSessionTerminatedGracefully(sessionTerminationInfo as SessionTerminationInfo),
        error: (err) => this.handleSessionTerminatedWithError(err),
      });
  }

  protected getProtocol(): ProtocolString {
    return 'RDP';
  }
}
