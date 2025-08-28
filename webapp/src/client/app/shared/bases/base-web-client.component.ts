import { Directive } from '@angular/core';
import { GatewayAlertMessageService } from '@shared/components/gateway-alert-message/gateway-alert-message.service';
import { ComponentStatus } from '@shared/models/component-status.model';
import { BaseSessionComponent } from '../models/web-session.model';
import { AnalyticService, ConnectionIdentifier, ProtocolString } from '../services/analytic.service';

export interface WebComponentReady {
  webComponentReady(event: Event, webSessionId: string): void;
}

@Directive()
export abstract class WebClientBaseComponent extends BaseSessionComponent {
  hideSpinnerOnly = false;
  error: string;
  loading = true;

  analyticHandle: ConnectionIdentifier;

  currentStatus: ComponentStatus = {
    id: undefined,
    isInitialized: false,
    isDisabled: false,
    isDisabledByUser: false,
  };

  protected constructor(
    protected gatewayAlertMessageService: GatewayAlertMessageService,
    protected analyticService: AnalyticService,
  ) {
    super();
  }

  abstract removeWebClientGuiElement(): void;

  //For translation 'ConnectionSuccessful
  protected webClientConnectionSuccess(message = 'Connection successful'): void {
    this.hideSpinnerOnly = true;
    this.gatewayAlertMessageService.addSuccess(message);
    this.analyticHandle = this.analyticService.sendOpenEvent(this.getProtocol());
  }

  protected webClientSuccess(message: string): void {
    this.gatewayAlertMessageService.addSuccess(message);
  }

  protected webClientError(errorMessage: string): void {
    this.gatewayAlertMessageService.addError(errorMessage);
    console.error(errorMessage);
  }

  protected webClientConnectionClosed(): void {
    if (this.analyticHandle) {
      this.analyticService.sendCloseEvent(this.analyticHandle);
    }
  }

  protected getIronErrorMessage(errorData: { backtrace: () => string } | string): string {
    return typeof errorData === 'string' ? errorData : errorData.backtrace();
  }

  protected abstract getProtocol(): ProtocolString;
}
