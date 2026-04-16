import { Component, OnDestroy, OnInit, Renderer2 } from '@angular/core';
import { DesktopWebClientBaseComponent } from '@shared/bases/desktop-web-client-base.component';
import { GatewayAlertMessageService } from '@shared/components/gateway-alert-message/gateway-alert-message.service';
import { ScreenScale } from '@shared/enums/screen-scale.enum';
import { IronARDConnectionParameters } from '@shared/interfaces/connection-params.interfaces';
import { ArdFormDataInput } from '@shared/interfaces/forms.interfaces';
import { UtilsService } from '@shared/services/utils.service';
import { DefaultArdPort, WebClientService } from '@shared/services/web-client.service';
import { WebSessionService } from '@shared/services/web-session.service';
import { MessageService } from 'primeng/api';
import { EMPTY, from, Observable, of } from 'rxjs';
import { catchError, map, switchMap, takeUntil, tap } from 'rxjs/operators';
import '@devolutions/iron-remote-desktop/iron-remote-desktop.js';
import { ardQualityMode, Backend, resolutionQuality, wheelSpeedFactor } from '@devolutions/iron-remote-desktop-vnc';
import { DVL_ARD_ICON, JET_ARD_URL } from '@gateway/app.constants';
import { AnalyticService, ProtocolString } from '@gateway/shared/services/analytic.service';
import { WheelSpeedControl } from '@shared/components/floating-session-toolbar/models/floating-session-toolbar-config.model';
import { ExtractedHostnamePort } from '@shared/services/utils/string.service';
import { v4 as uuidv4 } from 'uuid';

@Component({
  standalone: false,
  templateUrl: 'web-client-ard.component.html',
  styleUrls: ['web-client-ard.component.scss'],
  providers: [MessageService],
})
export class WebClientArdComponent
  extends DesktopWebClientBaseComponent<ArdFormDataInput>
  implements OnInit, OnDestroy
{
  backendRef = Backend;

  // ── Floating toolbar state ─────────────────────────────────────────────────
  wheelSpeed = 1;
  // sessionInfo / sessionInfoUrl / sessionInfoUsername / refreshSessionInfo() inherited from WebClientBaseComponent
  readonly wheelSpeedControl: WheelSpeedControl = {
    label: 'Wheel speed',
    min: 0.1,
    max: 3,
    step: 0.1,
  };
  // ──

  constructor(
    protected renderer: Renderer2,
    protected utils: UtilsService,
    protected gatewayAlertMessageService: GatewayAlertMessageService,
    protected webSessionService: WebSessionService,
    private webClientService: WebClientService,
    protected analyticService: AnalyticService,
  ) {
    super(renderer, webSessionService, gatewayAlertMessageService, analyticService);
  }

  ngOnInit(): void {
    this.webSessionIcon = DVL_ARD_ICON;
    this.refreshSessionInfo();

    super.ngOnInit();
  }

  // ── Floating toolbar handlers ─────────────────────────────────────────────
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

  protected handleExitFullScreenEvent(): void {
    this.isFullScreenMode = false;

    this.scaleTo(ScreenScale.Fit);
  }
  // ──

  protected startConnectionProcess(): void {
    this.getFormData()
      .pipe(
        takeUntil(this.destroyed$),
        tap(() => this.setupClipboardHandling(this.formData.autoClipboard)),
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
        this.formData = currentWebSession.data as ArdFormDataInput;
        this.wheelSpeed = this.formData.wheelSpeedFactor ?? 1;
        this.sessionInfoUsername = this.formData.username || null;
        this.refreshSessionInfo();
      }),
    );
  }

  private fetchParameters(formData: ArdFormDataInput): Observable<IronARDConnectionParameters> {
    const { hostname, username, password, resolutionQuality, ardQualityMode, wheelSpeedFactor = 1 } = formData;
    const extractedData: ExtractedHostnamePort = this.utils.string.extractHostnameAndPort(hostname, DefaultArdPort);

    const sessionId: string = uuidv4();
    const gatewayAddress = this.getGatewayWebSocketUrl(JET_ARD_URL, sessionId);
    this.sessionInfoUrl = this.toUserFacingUrl(gatewayAddress);
    this.sessionInfoUsername = username || null;
    this.refreshSessionInfo();

    const connectionParameters: IronARDConnectionParameters = {
      username,
      password,
      host: extractedData.hostname,
      port: extractedData.port,
      gatewayAddress,
      resolutionQuality,
      ardQualityMode,
      wheelSpeedFactor,
      sessionId,
    };
    return of(connectionParameters);
  }

  private fetchTokens(params: IronARDConnectionParameters): Observable<IronARDConnectionParameters> {
    return this.webClientService.fetchArdToken(params);
  }

  protected callConnect(connectionParameters: IronARDConnectionParameters): void {
    const configBuilder = this.remoteClient
      .configBuilder()
      .withUsername(connectionParameters.username)
      .withPassword(connectionParameters.password)
      .withDestination(connectionParameters.host)
      .withProxyAddress(connectionParameters.gatewayAddress)
      .withAuthToken(connectionParameters.token);

    if (connectionParameters.resolutionQuality != null) {
      configBuilder.withExtension(resolutionQuality(connectionParameters.resolutionQuality));
    }

    if (connectionParameters.ardQualityMode != null) {
      configBuilder.withExtension(ardQualityMode(connectionParameters.ardQualityMode));
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

  protected getProtocol(): ProtocolString {
    return 'ARD';
  }
}
