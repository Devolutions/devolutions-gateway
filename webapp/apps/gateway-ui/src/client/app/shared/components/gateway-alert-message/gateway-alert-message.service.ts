import { Injectable } from '@angular/core';
import type { ToastMessageOptions } from 'primeng/api';
import { Subject } from 'rxjs';

enum MessageSeverity {
  Success = 'success',
  Info = 'info',
  Warning = 'warn',
  Error = 'error',
}

@Injectable()
export class GatewayAlertMessageService {
  private messageSource = new Subject<ToastMessageOptions>();
  messageObserver = this.messageSource.asObservable();

  constructor() {}

  addSuccess(content: string): void {
    const message: ToastMessageOptions = this.buildMessageObject(MessageSeverity.Success, content);
    this.addMessage(message);
  }

  addInfo(content: string): void {
    const message: ToastMessageOptions = this.buildMessageObject(MessageSeverity.Info, content);
    this.addMessage(message);
  }
  addWarning(content: string): void {
    const message: ToastMessageOptions = this.buildMessageObject(MessageSeverity.Warning, content);
    this.addMessage(message);
  }
  addError(content: string): void {
    const message: ToastMessageOptions = this.buildMessageObject(MessageSeverity.Error, content);
    this.addMessage(message);
  }

  private buildMessageObject(severity: string, content: string): ToastMessageOptions {
    return {
      key: 'message',
      severity: severity,
      summary: '',
      detail: content,
    };
  }

  private addMessage(message: ToastMessageOptions): void {
    if (message) {
      message.detail = message.summary ? message.summary : message.detail;
      message.summary = '';
      message.life = 5000;
      this.messageSource.next(message);
    }
  }
}
