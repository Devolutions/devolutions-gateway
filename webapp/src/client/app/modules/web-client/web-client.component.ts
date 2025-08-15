import { Component } from '@angular/core';
import { TabViewComponent } from '@gateway/shared/components/tab-view/tab-view.component';
import { BaseComponent } from '@shared/bases/base.component';

@Component({
  templateUrl: 'web-client.component.html',
  styleUrls: ['web-client.component.scss'],
  standalone: true,
  imports: [TabViewComponent],
})
export class WebClientComponent extends BaseComponent {
  constructor() {
    super();
  }
}
