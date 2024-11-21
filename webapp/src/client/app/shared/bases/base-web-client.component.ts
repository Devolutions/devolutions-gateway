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

  protected webClientConnectionFail(message?: string, trace?: string): void {
    this.hideSpinnerOnly = true;
    //For translation 'ConnectionErrorPleaseVerifyYourConnectionSettings'
    const errorMessage = message || 'Connection error: Please verify your connection settings.';
    this.gatewayAlertMessageService.addError(errorMessage);
    console.error(errorMessage);

    if (trace) {
      console.error(trace);
    }

    this.analyticService.sendCloseEvent(this.analyticHandle);
  }

  protected webClientConnectionClosed(): void {
    this.analyticService.sendCloseEvent(this.analyticHandle);
  }

  protected abstract getProtocol(): ProtocolString;
}
