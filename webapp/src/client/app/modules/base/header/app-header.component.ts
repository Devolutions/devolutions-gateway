import { Component } from '@angular/core';
import { BaseComponent } from '@shared/bases/base.component';

@Component({
  selector: 'app-header',
  templateUrl: 'app-header.component.html',
  styleUrls: ['app-header.component.scss'],
})
export class AppHeaderComponent extends BaseComponent {
  focus = false;

  constructor() {
    super();
  }
}
