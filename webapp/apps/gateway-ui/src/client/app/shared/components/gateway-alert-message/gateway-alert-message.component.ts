import { Component, OnInit, ViewChild } from '@angular/core';
import { MessageService } from 'primeng/api';
import { Toast } from 'primeng/toast';
import { filter, takeUntil } from 'rxjs/operators';

import { BaseComponent } from '../../bases/base.component';
import { GatewayAlertMessageService } from './gateway-alert-message.service';

@Component({
  selector: 'gateway-alert-message',
  templateUrl: 'gateway-alert-message.component.html',
  styleUrls: ['gateway-alert-message.component.scss'],
})
export class GatewayAlertMessageComponent extends BaseComponent implements OnInit {
  @ViewChild('confirmMessageToast') confirmMessageToast: Toast;

  constructor(
    private gatewayMessageService: GatewayAlertMessageService,
    private messageService: MessageService,
  ) {
    super();
  }

  ngOnInit(): void {
    this.gatewayMessageService.messageObserver
      .pipe(
        filter((message) => !!message),
        takeUntil(this.destroyed$),
      )
      .subscribe((message) => {
        this.messageService.add(message);
      });
  }
}
