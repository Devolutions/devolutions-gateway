import { Directive } from '@angular/core';
import { BaseComponent } from '@shared/bases/base.component';
import { ActivatedRoute, Params } from '@angular/router';
import {WebClientQueryParams} from "@shared/services/web-client.service";

@Directive()
export abstract class WebClientBaseComponent extends BaseComponent {

  progressionText: string;
  error: string;

  protected constructor() {
    super();
    this.setProgressionText('LoadingWebPage');
  }

  abstract removeWebClientGuiElement(): void ;

  protected webClientConnectionSuccess(message?:string): void {
    if (!message) {
      //TODO var for translation 'ConnectionSuccessful'
      console.log('TODO: Display to screen---> Connection successful')
      return;
    }

    console.log(message);
  }

  protected webClientConnecting() {
    //TODO message to user connecting
  }

  protected webClientConnectionFail(message?:string, trace?: string): void {

    // TODO: Replace console.error with a more user-friendly error display mechanism
    // For example, using a toast notification service or error dialog
    // this.toastService.showError(errorMessage);

    if (!message) {
      //TODO var for translation 'ConnectionErrorPleaseVerifyYourConnectionSettings'
      console.error('TODO: Display to screen---> Connection error: Please verify your connection settings.')
      return;
    }
    console.error(message);

    if (trace) {
      console.error(trace);
    }
  }

  protected webClientConnectionClosed(message?:string): void {
    //TODO message to user connection closed
    if (!message) {
      //TODO var for translation 'connection closed'
      console.log('TODO: Display to screen---> Connection Closed.')
      return;
    }

    console.log(message);
  }

  protected webClientConnectionTimeout(message?:string): void {
    //TODO message to user connection timeout
    if (!message) {
      //TODO var for translation 'connection time out'
      console.log('TODO: Display to screen---> Connection timeout.')
      return;
    }

    console.log(message);
  }

  protected setProgressionText(text: string) {
    this.progressionText = text;
  }

  protected getProtocol(gatewayUrl: URL): string {
    return gatewayUrl.protocol.toUpperCase().indexOf('HTTPS') > -1 ? 'wss' : 'ws';
  }

  protected ensureEndWithSlash(path: string): string {
    return path.endsWith('/') ? path : path + '/';
  }

  protected isCredentialsEmpty(credential): boolean {
    return credential.username === '' && credential.domain === '' && credential.safePassword === '';
  }
}
