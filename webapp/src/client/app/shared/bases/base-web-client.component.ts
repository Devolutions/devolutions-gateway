import { Directive } from '@angular/core';
import { BaseComponent } from '@shared/bases/base.component';
import {GatewayAlertMessageService} from "@shared/components/gateway-alert-message/gateway-alert-message.service";
import { AnalyticService, ConnectionIndentifier, ProtocolString } from '../services/analytic.service';

@Directive()
export abstract class WebClientBaseComponent extends BaseComponent {

  static DVL_WARNING_ICON: string = 'dvl-icon-warning';

  hideSpinnerOnly: boolean = false;
  error: string;

  analyticHandle: ConnectionIndentifier

  protected constructor(protected gatewayAlertMessageService: GatewayAlertMessageService, protected analyticService:AnalyticService) {
    super();
  }

  abstract removeWebClientGuiElement(): void;

  protected webClientConnectionSuccess(message?:string): void {
    this.hideSpinnerOnly = true;

    if (!message) {
      //For translation 'ConnectionSuccessful
      message = 'Connection successful';
    }
    this.gatewayAlertMessageService.addSuccess(message);
    this.analyticHandle = this.analyticService.sendOpenEvent(this.getProtocol());
  }

  protected webClientConnectionFail(message?:string, trace?: string): void {
    this.hideSpinnerOnly = true;

    if (!message) {
      //For translation 'ConnectionErrorPleaseVerifyYourConnectionSettings'
      message = 'Connection error: Please verify your connection settings.';
    }
    this.gatewayAlertMessageService.addError(message);
    console.error(message);

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
