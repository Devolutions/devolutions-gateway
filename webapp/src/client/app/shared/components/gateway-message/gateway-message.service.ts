import {Injectable} from '@angular/core';
import {Subject} from 'rxjs';
import {Message} from 'primeng/api';

@Injectable()
export class GatewayMessageService {

  private messageSource = new Subject<Message | ConfirmMessage>();
  messageObserver = this.messageSource.asObservable();

  constructor() {
  }
  addSuccess(content: string) {
    this.addMessage({
      key: 'message',
      severity: 'success',
      summary: '',
      detail: content,
    });
  }
  addInfo(content: string) {
    this.addMessage({
      key: 'message',
      severity: 'info',
      summary: '',
      detail: content,
    });
  }
  addWarning(content: string) {
    this.addMessage({
      key: 'message',
      severity: 'warn',
      summary: '',
      detail: content,
    });
  }
  addError(content: string) {
    this.addMessage({
      key: 'message',
      severity: 'error',
      summary: '',
      detail: content,
    });
  }
  addConfirmSuccess(content: string,
                    title: string = '',
                    confirmMessageId: any = null,
                    icon?: string,
                    acceptLabel?: string,
                    accept?: (checkboxValue?: boolean) => void,
                    rejectLabel?: string,
                    reject?: (checkboxValue?: boolean) => void) {

    this.addConfirmMessage({
      id: confirmMessageId,
      key: 'confirm-message',
      severity: 'success',
      summary: title,
      detail: content,
      icon: icon,
      acceptLabel: acceptLabel,
      rejectLabel: rejectLabel,
      accept: accept,
      reject: reject,
    });
  }
  addConfirmWarning(content: string,
                    title: string = '',
                    confirmMessageId: any = null,
                    icon?: string,
                    acceptLabel?: string,
                    accept?: (checkboxValue?: boolean) => void,
                    rejectLabel?: string,
                    reject?: (checkboxValue?: boolean) => void,
                    optionCheckboxLabel?: string,
                    showCheckbox?: boolean) {

    this.addConfirmMessage({
      id: confirmMessageId,
      key: 'confirm-message',
      severity: 'warn',
      summary: title,
      detail: content,
      icon: icon,
      acceptLabel: acceptLabel,
      rejectLabel: rejectLabel,
      accept: accept,
      reject: reject,
      optionCheckboxLabel: optionCheckboxLabel,
      showCheckbox: showCheckbox,
    });
  }
  addConfirmError(content: string,
                  title: string = '',
                  confirmMessageId: any = null,
                  icon?: string,
                  acceptLabel?: string,
                  accept?: (checkboxValue?: boolean) => void,
                  rejectLabel?: string,
                  reject?: (checkboxValue?: boolean) => void) {

    this.addConfirmMessage({
      id: confirmMessageId,
      key: 'confirm-message',
      severity: 'error',
      summary: title,
      detail: content,
      icon: icon,
      acceptLabel: acceptLabel,
      rejectLabel: rejectLabel,
      accept: accept,
      reject: reject,
    });
  }
  private addConfirmMessage(message: ConfirmMessage) {
    if (message) {
      message.sticky = true;
      message.closable = false;
      this.messageSource.next(message);
    }
  }

  private addMessage(message: Message) {
    if (message) {
      message.detail = !!message.summary ? message.summary : message.detail;
      message.summary = '';
      message.life = 5000;
      this.messageSource.next(message);
    }
  }
}

export interface ConfirmMessage extends Message {
  icon?: string;
  acceptLabel?: string;
  rejectLabel?: string;
  accept?: (checkboxValue?: boolean) => void;
  reject?: (checkboxValue?: boolean) => void;
  optionCheckboxLabel?: string;
  showCheckbox?: boolean;
}
