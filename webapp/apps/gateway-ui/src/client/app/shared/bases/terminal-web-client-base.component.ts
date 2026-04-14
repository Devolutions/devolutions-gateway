import { Directive, EventEmitter, OnDestroy, Output } from '@angular/core';
import { DVL_WARNING_ICON } from '@gateway/app.constants';
import { GatewayAlertMessageService } from '@shared/components/gateway-alert-message/gateway-alert-message.service';
import { ComponentStatus } from '@shared/models/component-status.model';
import { ToastMessageOptions } from 'primeng/api';
import { Subject } from 'rxjs';
import { AnalyticService } from '../services/analytic.service';
import { WebSessionService } from '../services/web-session.service';
import { WebClientBaseComponent } from './base-web-client.component';

@Directive()
export abstract class TerminalWebClientBaseComponent extends WebClientBaseComponent implements OnDestroy {
  rightToolbarButtons = [
    { label: 'Close Session', icon: 'dvl-icon dvl-icon-close', action: () => this.startTerminationProcess() },
  ];

  // ── Terminal session state ──────────────────────────────────────────────
  clientError: string;
  protected removeElement = new Subject<unknown>();

  /** Unsubscribe function for the lifecycle onStatusChange handler. */
  protected unsubscribeTerminalEvent: (() => void) | null = null;
  /** Unsubscribe function for the connecting-message onStatusChange handler. */
  protected unsubscribeConnectionListener: (() => void) | null = null;

  @Output() readonly componentStatus = new EventEmitter<ComponentStatus>();
  @Output() readonly sizeChange = new EventEmitter<void>();

  protected constructor(
    protected override gatewayAlertMessageService: GatewayAlertMessageService,
    protected webSessionService: WebSessionService,
    protected override analyticService: AnalyticService,
  ) {
    super(gatewayAlertMessageService, analyticService);
  }

  ngOnDestroy(): void {
    this.removeRemoteTerminalListener();
    this.removeWebClientGuiElement();
    if (this.currentStatus.isInitialized && !this.currentStatus.isDisabled) {
      this.startTerminationProcess();
    }
    // Break the reference cycle: component → remoteTerminal → onStatusChange closures → component
    this.teardownTerminalClient();
    super.ngOnDestroy();
  }

  /** Icon shown on the session tab when the terminal connects successfully. */
  protected abstract getSuccessIcon(): string;
  protected abstract startTerminationProcess(): void;
  abstract sendTerminateSessionCmd(): void;
  protected abstract removeWebClientGuiElement(): void;
  /**
   * Null out the terminal client reference to break the reference cycle that
   * would prevent GC of the component tree after the session is closed.
   * Called by the base ngOnDestroy after the terminal has been closed.
   */
  protected abstract teardownTerminalClient(): void;

  /** Cancels all onStatusChange subscriptions registered by the subclass. */
  protected removeRemoteTerminalListener(): void {
    this.unsubscribeTerminalEvent?.();
    this.unsubscribeTerminalEvent = null;
    this.unsubscribeConnectionListener?.();
    this.unsubscribeConnectionListener = null;
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
    if (this.currentStatus.isDisabled) {
      return;
    }

    // Pre-connect close/error paths can run before initializeStatus().
    // Backfill id so dynamic tab removal receives a valid session id.
    this.currentStatus.id ??= this.webSessionId;
    this.currentStatus.isDisabled = true;
    if (!this.currentStatus.id) {
      return;
    }
    this.componentStatus.emit(this.currentStatus);
  }

  /** Called when the terminal GUI signals a successful connection. */
  protected handleClientConnectStarted(): void {
    this.loading = false;
    void this.webSessionService.updateWebSessionIcon(this.webSessionId, this.getSuccessIcon());
    this.webClientConnectionSuccess();
  }

  /**
   * Called when the session ends for any reason (graceful close, error, timeout).
   * Exits fullscreen, updates the tab icon, stores the error message, and
   * disables the component status.
   *
   * @param errorMessage Human-readable message stored in `clientError`.
   * @param isError      When true, the tab icon is updated to the warning icon;
   *                     when false, the success icon is used instead.
   */
  protected handleSessionEnded(errorMessage: string, isError = true): void {
    if (document.fullscreenElement) {
      document.exitFullscreen().catch((err) => {
        console.error(`Error attempting to exit fullscreen: ${err}`);
      });
    }

    this.clientError = errorMessage;
    void this.webSessionService.updateWebSessionIcon(
      this.webSessionId,
      isError ? DVL_WARNING_ICON : this.getSuccessIcon(),
    );
    this.currentStatus.terminationMessage = {
      summary: errorMessage,
      severity: isError ? 'error' : 'success',
    } as ToastMessageOptions;
    this.disableComponentStatus();
    this.webClientConnectionClosed();
  }

  /**
   * Called when a connection-phase error occurs (e.g. fetch-token failure).
   * Sets `clientError`, logs to console, and disables the component.
   */
  protected handleConnectionError(message: string): void {
    this.clientError = message;
    console.error(message);
    void this.webSessionService.updateWebSessionIcon(this.webSessionId, DVL_WARNING_ICON);
    this.currentStatus.terminationMessage = {
      summary: message,
      severity: 'error',
    } as ToastMessageOptions;
    this.disableComponentStatus();
  }
}
