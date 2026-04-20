import {
  AfterViewInit,
  Directive,
  ElementRef,
  EventEmitter,
  HostListener,
  Input,
  OnDestroy,
  Output,
  Renderer2,
  ViewChild,
} from '@angular/core';
import { IronError, SessionTerminationInfo, UserInteraction } from '@devolutions/iron-remote-desktop';
import { DVL_WARNING_ICON } from '@gateway/app.constants';
import { ClipboardActionButton } from '@shared/components/floating-session-toolbar/models/floating-session-toolbar-action.model';
import { ScreenMode } from '@shared/components/floating-session-toolbar/models/floating-session-toolbar-config.model';
import { GatewayAlertMessageService } from '@shared/components/gateway-alert-message/gateway-alert-message.service';
import { ScreenScale } from '@shared/enums/screen-scale.enum';
import {
  IronARDConnectionParameters,
  IronRDPConnectionParameters,
  IronVNCConnectionParameters,
} from '@shared/interfaces/connection-params.interfaces';
import { DesktopFormDataInput } from '@shared/interfaces/forms.interfaces';
import { ComponentStatus } from '@shared/models/component-status.model';
import { WebSessionService } from '@shared/services/web-session.service';
import { Subject } from 'rxjs';
import { takeUntil } from 'rxjs/operators';
import { UAParser } from 'ua-parser-js';
import { AnalyticService } from '../services/analytic.service';
import { WebClientBaseComponent } from './base-web-client.component';

enum IronErrorKind {
  General = 0,
  WrongPassword = 1,
  LogonFailure = 2,
  AccessDenied = 3,
  RDCleanPath = 4,
  ProxyConnect = 5,
}

@Directive()
export abstract class DesktopWebClientBaseComponent<TFormData extends DesktopFormDataInput>
  extends WebClientBaseComponent
  implements AfterViewInit, OnDestroy
{
  // ── Clipboard state — shared by desktop protocol components only ──────────
  formData: TFormData;

  protected removeElement: Subject<unknown> = new Subject();
  private remoteClientEventListener: (event: Event) => void;
  // unlistenRemoteClient and removeRemoteClientListener() live in DesktopWebClientBaseComponent

  protected remoteClient: UserInteraction;
  saveRemoteClipboardButtonEnabled = false;

  protected webSessionIcon: string;

  clipboardActionButtons: ClipboardActionButton[] = [];

  isFullScreenMode = false;
  cursorOverrideActive = false;

  @Input() webSessionId: string;
  @Input() sessionsContainerElement: ElementRef;

  @Output() readonly componentStatus = new EventEmitter<ComponentStatus>();
  @Output() readonly sizeChange = new EventEmitter<void>();

  @ViewChild('ironRemoteDesktopElement') ironRemoteDesktopElement: ElementRef;

  /** Stored so it can be called to remove the 'ready' event listener on destroy. */
  protected unlistenRemoteClient: (() => void) | null = null;

  protected abstract startConnectionProcess(): void;
  protected abstract handleExitFullScreenEvent(): void;
  protected abstract callConnect(
    connectionParameters: IronVNCConnectionParameters | IronARDConnectionParameters | IronRDPConnectionParameters,
  ): void;

  protected constructor(
    protected renderer: Renderer2,
    protected webSessionService: WebSessionService,
    protected gatewayAlertMessageService: GatewayAlertMessageService,
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
    // Break the reference cycle:
    // protocol component → this.remoteClient → UserInteraction → callback closures → protocol component
    this.remoteClient = null;
    super.ngOnDestroy();
  }

  protected handleOnFullScreenEvent(): void {
    if (!document.fullscreenElement) {
      this.handleExitFullScreenEvent();
    }
  }

  protected toggleFullscreen(): void {
    this.isFullScreenMode = !this.isFullScreenMode;
    !document.fullscreenElement ? this.enterFullScreen() : this.exitFullScreen();

    this.scaleTo(ScreenScale.Full);
  }

  protected async enterFullScreen(): Promise<void> {
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

  protected exitFullScreen(): void {
    if (document.fullscreenElement) {
      document.exitFullscreen().catch((err) => {
        console.error(`Error attempting to exit fullscreen: ${err}`);
      });
    }
  }

  /** True when the remote client should handle clipboard automatically.
   *  For form-based connections the explicit autoClipboard field is used.
   *  When autoClipboard is undefined (URL/config-based RDP connections) the
   *  Blink engine is used as a reliable heuristic. */
  protected isAutoClipboardMode(autoClipboard?: boolean): boolean {
    if (autoClipboard !== undefined) return autoClipboard;
    return new UAParser().getEngine().name === 'Blink';
  }

  /** Populates clipboardActionButtons for manual clipboard workflows.
   *  Call after the component knows whether auto-clipboard is enabled.
   *  This intentionally lives in the shared desktop base instead of the thin
   *  protocol wrappers: the Blink/manual clipboard actions are stable across
   *  apps, while Hub, DVLS, and this webapp differ substantially in service
   *  wiring. Keeping the setup here prevents duplicate actions without turning
   *  wrappers into app-specific service containers.
   *  Assigns a deterministic action list so repeated calls are idempotent and
   *  cannot duplicate menu entries.
   *  Clears the list when in a non-secure context or when auto-clipboard is active. */
  protected setupClipboardHandling(autoClipboard?: boolean): void {
    if (!window.isSecureContext || this.isAutoClipboardMode(autoClipboard)) {
      this.clipboardActionButtons = [];
      return;
    }

    const actions: ClipboardActionButton[] = [
      {
        id: 'save-clipboard',
        label: 'Save Clipboard',
        tooltip: 'Copy received clipboard content to your local clipboard.',
        icon: 'dvl-icon dvl-icon-save',
        action: () => this.saveRemoteClipboard(),
        enabled: () => this.saveRemoteClipboardButtonEnabled,
      },
    ];

    // We don't check for clipboard write support, as all recent browser versions support it.
    // Check if the browser supports reading local clipboard.
    if (typeof navigator.clipboard?.readText === 'function') {
      actions.push({
        id: 'send-clipboard',
        label: 'Send Clipboard',
        tooltip: 'Send your local clipboard content to the remote server.',
        icon: 'dvl-icon dvl-icon-send',
        action: () => this.sendClipboard(),
        enabled: () => true,
      });
    }

    this.clipboardActionButtons = actions;
  }

  async saveRemoteClipboard(): Promise<void> {
    try {
      await this.remoteClient.saveRemoteClipboardData();
      this.webClientSuccess('Clipboard content has been copied to your clipboard!');
      this.saveRemoteClipboardButtonEnabled = false;
    } catch (err) {
      this.handleSessionError(err);
    }
  }

  async sendClipboard(): Promise<void> {
    try {
      await this.remoteClient.sendClipboardData();
      this.webClientSuccess('Clipboard content has been sent to the remote server!');
    } catch (err) {
      this.handleSessionError(err);
    }
  }

  protected handleSessionError(err: unknown): void {
    if (this.isIronError(err)) {
      this.webClientError(err.backtrace());
    } else {
      this.webClientError(`${err}`);
    }
  }

  protected isIronError(error: unknown): error is IronError {
    return (
      typeof error === 'object' &&
      error !== null &&
      typeof (error as IronError).backtrace === 'function' &&
      typeof (error as IronError).kind === 'function'
    );
  }

  protected getIronErrorMessageTitle(error: IronError): string {
    //For translation 'UnknownError'
    //For translation 'ConnectionErrorPleaseVerifyYourConnectionSettings'
    //For translation 'AccessDenied'
    const errorKind: IronErrorKind = error.kind().valueOf();
    switch (errorKind) {
      case IronErrorKind.General:
        return 'Unknown Error';
      case IronErrorKind.WrongPassword:
      case IronErrorKind.LogonFailure:
        return 'Connection error: Please verify your connection settings.';
      case IronErrorKind.AccessDenied:
        return 'Access denied';
      default:
        return 'Connection error: Please verify your connection settings.';
    }
  }

  protected initializeStatus(): void {
    this.currentStatus = {
      id: this.webSessionId,
      isInitialized: true,
      isDisabled: false,
      isDisabledByUser: false,
    };
  }

  protected disableComponentStatus(): void {
    // Pre-connect close/error paths can run before initializeStatus().
    // Backfill id so dynamic tab removal receives a valid session id.
    this.currentStatus.id ??= this.webSessionId;
    this.currentStatus.isDisabled = true;
    if (!this.currentStatus.id) {
      return;
    }
    this.currentStatus.terminationMessage = this.sessionTerminationMessage;
    this.componentStatus.emit(this.currentStatus);
  }

  /** Removes the 'ready' event listener added by the subclass. */
  protected removeRemoteClientListener(): void {
    if (this.unlistenRemoteClient) {
      this.unlistenRemoteClient();
      this.unlistenRemoteClient = null;
    }
  }

  protected removeWebClientGuiElement(): void {
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

  protected initiateRemoteClientListener(): void {
    this.remoteClientEventListener = (event: Event) => this.readyRemoteClientEventListener(event);
    this.unlistenRemoteClient = this.renderer.listen(
      this.ironRemoteDesktopElement.nativeElement,
      'ready',
      this.remoteClientEventListener,
    );
  }

  protected startTerminationProcess(): void {
    this.sendTerminateSessionCmd();
    this.currentStatus.isDisabledByUser = true;
    this.disableComponentStatus();
  }

  sendTerminateSessionCmd(): void {
    if (!this.currentStatus.isInitialized || !this.remoteClient) {
      return;
    }
    this.currentStatus.isInitialized = false;
    this.remoteClient.shutdown();
  }

  scaleTo(scale: ScreenScale): void {
    this.remoteClient.setScale(scale.valueOf());
  }

  /** Shared handler for the toolbar's screenModeChange output.
   *  Identical in RDP, VNC, and ARD — lives here to avoid duplication. */
  handleScreenModeChange(mode: ScreenMode): void {
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

  /** Default behavior for the toolbar Session info button. */
  onSessionInfoPress(): void {
    this.gatewayAlertMessageService.addInfo(`Session ID: ${this.webSessionId}`);
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

  protected readyRemoteClientEventListener(event: Event): void {
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

  protected handleSessionStarted(): void {
    this.loading = false;
    this.remoteClient.setVisibility(true);
    void this.webSessionService.updateWebSessionIcon(this.webSessionId, this.webSessionIcon);
    this.webClientConnectionSuccess();
    this.initializeStatus();
  }

  protected handleSessionTerminatedWithError(error: unknown): void {
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

  protected handleError(error: string): void {
    this.loading = false;
    this.sessionTerminationMessage = {
      summary: 'Unexpected error occurred',
      detail: error,
      severity: 'error',
    };

    this.disableComponentStatus();
  }

  protected handleSessionTerminatedGracefully(sessionTerminationInfo: SessionTerminationInfo): void {
    this.sessionTerminationMessage = {
      summary: 'Session terminated gracefully',
      detail: sessionTerminationInfo.reason(),
      severity: 'success',
    };

    this.handleSessionTerminated();
  }

  protected handleSessionTerminated(): void {
    this.loading = false;
    if (document.fullscreenElement) {
      this.exitFullScreen();
    }

    this.disableComponentStatus();
    super.webClientConnectionClosed();
  }
}
