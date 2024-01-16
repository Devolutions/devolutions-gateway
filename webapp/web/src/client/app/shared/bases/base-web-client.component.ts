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
      console.log('Connection successful')
    } else {
      console.log(message);
    }
  }

  protected webClientConnecting() {
    //TODO message to user connecting
  }

  protected webClientConnectionFail(message?:string): void {
    if (!message) {
      //TODO var for translation 'ConnectionErrorPleaseVerifyYourConnectionSettings'
      console.log('Connection error: Please verify your connection settings.')
    } else {
      console.log(message);
    }
  }

  protected webClientConnectionClosed() {
    //TODO message to user connection closed
  }

  protected webClientConnectionTimeout() {
    //TODO message to user connection timeout
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
