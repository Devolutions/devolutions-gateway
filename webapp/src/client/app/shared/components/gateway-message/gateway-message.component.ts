import {Component, OnInit, ViewChild} from '@angular/core';
import {filter, takeUntil} from 'rxjs/operators';
import {MessageService} from 'primeng/api';
import {Toast} from 'primeng/toast';

import {BaseComponent} from '../../bases/base.component'
import {ConfirmMessage, GatewayMessageService} from './gateway-message.service';


@Component({
  selector: 'gateway-message',
  templateUrl: 'gateway-message.component.html',
  styleUrls: ['gateway-message.component.scss']
})

export class GatewayMessageComponent extends BaseComponent implements OnInit {
  @ViewChild('confirmMessageToast') confirmMessageToast: Toast;

  checkBoxValue = false;

  constructor(private gatewayMessageService: GatewayMessageService,
              private messageService: MessageService){
    super();
  }

  ngOnInit(): void {
    this.gatewayMessageService.messageObserver
      .pipe(
        filter(message => !!message),
        takeUntil(this.destroyed$))
      .subscribe(message => {
        if (this.confirmMessageToast.messages && message.id) {
          this.onCloseConfirmMessageById(message.id);
        }
        this.checkBoxValue = false;
        this.messageService.add(message);
      });
  }

  onAcceptConfirmMessage(confirmMessage: ConfirmMessage) {
    confirmMessage.accept(this.checkBoxValue);
    this.onCloseConfirmMessage(confirmMessage);
  }

  onRejectConfirmMessage(confirmMessage: ConfirmMessage) {
    if (confirmMessage.reject) {
      confirmMessage.reject(this.checkBoxValue);
    }
    this.onCloseConfirmMessage(confirmMessage);
  }

  onCloseConfirmMessage(confirmMessage: ConfirmMessage) {
    this.confirmMessageToast.messages.splice(this.confirmMessageToast.messages.findIndex(m => m === confirmMessage), 1);
  }

  onCloseConfirmMessageById(confirmMessageId: any) {
    this.confirmMessageToast.messages.splice(this.confirmMessageToast.messages.findIndex(m => m.id === confirmMessageId), 1);
  }
}
