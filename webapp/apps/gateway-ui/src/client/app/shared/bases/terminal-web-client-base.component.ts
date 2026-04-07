import { Directive, EventEmitter, Output } from '@angular/core';
import { DVL_WARNING_ICON } from '@gateway/app.constants';
import { GatewayAlertMessageService } from '@shared/components/gateway-alert-message/gateway-alert-message.service';
import { ComponentStatus } from '@shared/models/component-status.model';
import type { ToastMessageOptions } from 'primeng/api';
import { Subject } from 'rxjs';
import { AnalyticService } from '../services/analytic.service';
import { WebSessionService } from '../services/web-session.service';
import { WebClientBaseComponent } from './base-web-client.component';

@Directive()
export abstract class TerminalWebClientBaseComponent extends WebClientBaseComponent {
  // ── Terminal session state ──────────────────────────────────────────────
  /** Structured message passed to <web-client-form> after the session ends. */
  sessionTerminationMessage: ToastMessageOptions;
  protected removeElement = new Subject<unknown>();

  @Output() readonly componentStatus = new EventEmitter<ComponentStatus>();
  @Output() readonly sizeChange = new EventEmitter<void>();

  protected constructor(
    protected override gatewayAlertMessageService: GatewayAlertMessageService,
    protected webSessionService: WebSessionService,
    protected override analyticService: AnalyticService,
  ) {
    super(gatewayAlertMessageService, analyticService);
  }

  /** Icon shown on the session tab when the terminal connects successfully. */
  protected abstract getSuccessIcon(): string;

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

    this.currentStatus.isDisabled = true;
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
   * Exits fullscreen, updates the tab icon, stores the termination message, and
   * disables the component status.
   *
   * @param message  Human-readable message shown on the reconnect form.
   * @param isError  When true, severity is 'error' and the warning icon is used;
   *                 when false, severity is 'success' and the protocol icon is used.
   */
  protected handleSessionEnded(message: string, isError = true): void {
    if (document.fullscreenElement) {
      document.exitFullscreen().catch((err) => {
        console.error(`Error attempting to exit fullscreen: ${err}`);
      });
    }

    this.sessionTerminationMessage = {
      summary: message,
      severity: isError ? 'error' : 'success',
    };
    void this.webSessionService.updateWebSessionIcon(
      this.webSessionId,
      isError ? DVL_WARNING_ICON : this.getSuccessIcon(),
    );
    this.disableComponentStatus();
    this.webClientConnectionClosed();
  }

  /**
   * Called when a connection-phase error occurs (e.g. fetch-token failure).
   * Sets the termination message, logs to console, and disables the component.
   */
  protected handleConnectionError(message: string): void {
    this.sessionTerminationMessage = { summary: message, severity: 'error' };
    console.error(message);
    void this.webSessionService.updateWebSessionIcon(this.webSessionId, DVL_WARNING_ICON);
    this.disableComponentStatus();
  }
}
