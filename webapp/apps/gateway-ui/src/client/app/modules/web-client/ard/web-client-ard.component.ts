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
import {
  ardControlMode,
  ardControlStateCallback,
  ardCurtainFailedCallback,
  ardHideCurtain,
  ardOnlyInputEncryption,
  ardQualityMode,
  ardShowCurtain,
  Backend,
  resolutionQuality,
  wheelSpeedFactor,
} from '@devolutions/iron-remote-desktop-vnc';
import { DVL_ARD_ICON, JET_ARD_URL } from '@gateway/app.constants';
import {
  ArdControlPending,
  ArdControlState,
  ArdCurtainFailure,
} from '@gateway/modules/web-client/ard/ard-control.model';
import { buildArdModeToggle, buildArdStatusBadges } from '@gateway/modules/web-client/ard/ard-control-toolbar';
import { AnalyticService, ProtocolString } from '@gateway/shared/services/analytic.service';
import {
  ClipboardActionButton,
  ToolbarAction,
} from '@shared/components/floating-session-toolbar/models/floating-session-toolbar-action.model';
import {
  ToolbarModeToggle,
  ToolbarStatusBadge,
  WheelSpeedControl,
} from '@shared/components/floating-session-toolbar/models/floating-session-toolbar-config.model';
import { ArdControlMode, ArdControlModes, DefaultArdStartMode } from '@shared/interfaces/ard-control.interfaces';
import { ExtractedHostnamePort } from '@shared/services/utils/string.service';
import { v4 as uuidv4 } from 'uuid';

// At connect time the session falls back to Observe; a later request keeps the current mode.
const StartModeNotAllowedMessage = "That mode isn't allowed. You're observing.";
const ModeNotAllowedMessage = "That mode isn't allowed";
const ControlRevokedMessage = 'The remote user no longer allows control';
const ControlGrantedMessage = 'Control is available again';
const ArdControlRequestFailedMessage = 'The control request failed';
const ArdControlTimedOutMessage = "The Mac didn't respond";

// Re-enables the controls if the session never settles a mode or hide-curtain request.
// Showing the curtain has no timeout: a mode request would cancel it, and the session settles every curtain request
// it sends on the Mac's next screen report.
const ArdPendingTimeoutMs = 10_000;

const Utf8Encoder = new TextEncoder();

const CurtainFailureMessages: Record<ArdCurtainFailure, string> = {
  'login-window': "Can't show the curtain while the Mac is at the login window",
  'lock-screen': "Can't show the curtain while the Mac is at its lock screen",
  'not-shown': "Can't show the curtain right now",
  'not-hidden': "Can't hide the curtain right now",
};

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

  // ── ARD control state ─────────────────────────────────────────────────────
  // Kept here rather than in the toolbar because the first report arrives before the first frame,
  // while the toolbar only exists once the session is live.
  // UNTESTED: only onArdControlState() assigns ardControl, so the UI never shows a state the Mac didn't confirm.
  // Only a settling report or curtain failure (see ArdControlPending), a rejected invokeExtension, or the timeout
  // clears ardPending; clearing it earlier lets a mode request cancel a curtain in flight.
  ardControl: ArdControlState | undefined;
  ardPending: ArdControlPending | undefined;
  private ardPendingTimeout: ReturnType<typeof setTimeout> | undefined;
  // Read only while a mode request is in flight.
  private ardRequestedMode: ArdControlMode = DefaultArdStartMode;
  private ardStartMode: ArdControlMode = DefaultArdStartMode;

  // Toolbar views of the ARD control state, rebuilt by refreshArdToolbar().
  ardModeToggle: ToolbarModeToggle | null = null;
  ardStatusBadges: ToolbarStatusBadge[] = [];
  ardSessionActions: ToolbarAction[] = [];

  curtainDialogVisible = false;
  curtainMessage = '';
  // Set only by onCurtainMessageChange().
  curtainMessageTooLong = false;
  // The session ends on a longer message.
  readonly maxCurtainMessageBytes = 512;
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

  ngOnDestroy(): void {
    clearTimeout(this.ardPendingTimeout);
    super.ngOnDestroy();
  }

  // ── Floating toolbar handlers ─────────────────────────────────────────────
  onCursorCrosshairChange(enabled: boolean): void {
    if (enabled !== this.cursorOverrideActive) {
      this.toggleCursorKind();
    }
  }

  toggleCursorKind(): void {
    this.cursorOverrideActive = !this.cursorOverrideActive;
    this.applyCursorStyle();
  }

  // The session drops input while observing; the default cursor signals that.
  private applyCursorStyle(): void {
    if (!this.remoteClient) {
      return;
    }
    if (this.ardControl?.mode === 'observe') {
      this.remoteClient.setCursorStyleOverride('default');
    } else if (this.cursorOverrideActive) {
      this.remoteClient.setCursorStyleOverride('url("assets/images/crosshair.png") 7 7, default');
    } else {
      this.remoteClient.setCursorStyleOverride(null);
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

  // ── ARD control handlers ──────────────────────────────────────────────────
  onArdModeChange(mode: string): void {
    const requested = ArdControlModes.find((known) => known === mode);
    if (!requested) {
      return;
    }
    this.ardRequestedMode = requested;
    this.invokeArdControl('mode', ardControlMode(requested));
  }

  onCurtainMessageChange(message: string): void {
    this.curtainMessage = message;
    this.curtainMessageTooLong = Utf8Encoder.encode(message).length > this.maxCurtainMessageBytes;
  }

  openCurtainDialog(): void {
    this.onCurtainMessageChange('');
    this.curtainDialogVisible = true;
  }

  submitCurtain(): void {
    if (this.curtainMessageTooLong || this.ardPending) {
      return;
    }
    this.curtainDialogVisible = false;
    this.invokeArdControl('show-curtain', ardShowCurtain(this.curtainMessage));
  }

  private invokeArdControl(pending: ArdControlPending, extension: unknown): void {
    this.setArdPending(pending);
    try {
      this.remoteClient.invokeExtension(extension);
    } catch (err) {
      // The session reports no state change for a request it rejected outright.
      this.setArdPending(undefined);
      this.webClientError(ArdControlRequestFailedMessage);
      console.error(err);
    }
  }

  private setArdPending(pending: ArdControlPending | undefined): void {
    clearTimeout(this.ardPendingTimeout);
    this.ardPending = pending;
    this.ardPendingTimeout =
      pending && pending !== 'show-curtain'
        ? setTimeout(() => this.onArdPendingTimeout(), ArdPendingTimeoutMs)
        : undefined;
    this.refreshArdToolbar();
  }

  private onArdPendingTimeout(): void {
    this.setArdPending(undefined);
    this.webClientWarning(ArdControlTimedOutMessage);
  }

  private refreshArdToolbar(): void {
    const state = this.ardControl;
    if (!state) {
      return;
    }
    this.ardModeToggle = buildArdModeToggle(state, this.ardPending);
    this.ardStatusBadges = buildArdStatusBadges(state);

    if (!state.curtainOn && !state.curtainAvailable) {
      this.ardSessionActions = [];
      return;
    }
    const { curtainOn } = state;
    this.ardSessionActions = [
      {
        id: curtainOn ? 'ard-hide-curtain' : 'ard-show-curtain',
        label: curtainOn ? 'Hide curtain' : 'Show curtain',
        tooltip: curtainOn
          ? 'Remove the curtain from the Mac and return to the previous control mode.'
          : "Take exclusive control and cover the Mac's screen with a curtain for the person at the Mac.",
        icon: curtainOn ? 'dvl-icon dvl-icon-wayk-session-on' : 'dvl-icon dvl-icon-wayk-session-off',
        section: 'Screen',
        action: curtainOn
          ? () => this.invokeArdControl('hide-curtain', ardHideCurtain())
          : () => this.openCurtainDialog(),
        enabled: () => !this.ardPending,
      },
    ];
  }

  private isArdPendingSettled(pending: ArdControlPending, state: ArdControlState): boolean {
    switch (pending) {
      case 'mode': {
        // The request is only queued, so a server report handled before it may arrive first.
        const requested = this.ardRequestedMode;
        return state.mode === requested || !state.availableModes.includes(requested);
      }
      // A failure is reported through onArdCurtainFailed() instead.
      case 'show-curtain':
        return state.curtainOn;
      case 'hide-curtain':
        return !state.curtainOn;
    }
  }

  private onArdCurtainFailed(failure: ArdCurtainFailure): void {
    if (this.ardPending && this.ardPending !== 'mode') {
      this.setArdPending(undefined);
    }
    this.webClientWarning(CurtainFailureMessages[failure]);
  }

  private onArdControlState(state: ArdControlState): void {
    const previous = this.ardControl;
    const pending = this.ardPending;
    const settled = pending !== undefined && this.isArdPendingSettled(pending, state);
    this.ardControl = state;
    if (settled) {
      this.setArdPending(undefined);
    } else {
      this.refreshArdToolbar();
    }
    this.applyCursorStyle();
    if (!state.curtainAvailable || state.curtainOn) {
      this.curtainDialogVisible = false;
    }

    if (!previous) {
      if (state.mode !== this.ardStartMode) {
        this.webClientWarning(StartModeNotAllowedMessage);
      }
      return;
    }

    // curtainAvailable alone also flips when the displayed session changes, so only availableModes tells
    // whether the remote user revoked or granted control.
    const hadControl = previous.availableModes.some((mode) => mode !== 'observe');
    const hasControl = state.availableModes.some((mode) => mode !== 'observe');
    const revoked = hadControl && !hasControl && state.mode === 'observe';

    if (settled) {
      if (pending === 'mode' && state.mode !== this.ardRequestedMode) {
        this.webClientWarning(revoked ? ControlRevokedMessage : ModeNotAllowedMessage);
      }
      return;
    }

    // A curtain change from the Mac's side updates the toolbar silently.
    if (revoked) {
      this.webClientWarning(ControlRevokedMessage);
    } else if (!hadControl && hasControl) {
      this.gatewayAlertMessageService.addInfo(ControlGrantedMessage);
    }
  }

  protected setupClipboardHandling(autoClipboard?: boolean): void {
    super.setupClipboardHandling(autoClipboard);
    // The session drops clipboard in both directions while observing.
    this.clipboardActionButtons = this.clipboardActionButtons.map(
      (button): ClipboardActionButton => ({
        ...button,
        enabled: () => this.ardControl?.mode !== 'observe' && button.enabled(),
      }),
    );
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
    const {
      hostname,
      username,
      password,
      resolutionQuality,
      ardQualityMode,
      wheelSpeedFactor = 1,
      ardOnlyInputEncryption,
      ardStartMode,
    } = formData;
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
      ardStartMode,
      wheelSpeedFactor,
      sessionId,
      ardOnlyInputEncryption,
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

    configBuilder.withExtension(ardOnlyInputEncryption(connectionParameters.ardOnlyInputEncryption));
    configBuilder.withExtension(wheelSpeedFactor(connectionParameters.wheelSpeedFactor));

    this.ardStartMode = connectionParameters.ardStartMode;
    configBuilder.withExtension(ardControlMode(connectionParameters.ardStartMode));
    configBuilder.withExtension(ardControlStateCallback((state) => this.onArdControlState(state)));
    configBuilder.withExtension(ardCurtainFailedCallback((failure) => this.onArdCurtainFailed(failure)));

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
