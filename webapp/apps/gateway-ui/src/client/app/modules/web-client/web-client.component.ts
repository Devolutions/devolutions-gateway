import { Component } from '@angular/core';
import { BaseComponent } from '@shared/bases/base.component';

@Component({
  standalone: false,
  templateUrl: 'web-client.component.html',
  styleUrls: ['web-client.component.scss'],
})
export class WebClientComponent extends BaseComponent {
  constructor() {
    super();
  }
}
