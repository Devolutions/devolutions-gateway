import { Directive } from '@angular/core';
import { BaseComponent } from '@shared/bases/base.component';
import {GatewayAlertMessageService} from "@shared/components/gateway-alert-message/gateway-alert-message.service";

@Directive()
export abstract class WebClientBaseComponent extends BaseComponent {

  static DVL_WARNING_ICON: string = 'dvl-icon-warning';

  hideSpinnerOnly: boolean = false;
  error: string;

  protected constructor(protected gatewayAlertMessageService: GatewayAlertMessageService) {
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
  }

  protected webClientConnectionClosed(message?:string): void {
    if (!message) {
      //For translation 'connection closed'
      message = 'Connection error: Please verify your connection settings.';
    }
    this.gatewayAlertMessageService.addInfo(message);
    console.warn(message);
  }
}
