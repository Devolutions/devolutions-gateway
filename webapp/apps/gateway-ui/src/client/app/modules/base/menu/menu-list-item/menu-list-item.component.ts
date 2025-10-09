import { Component, Input } from '@angular/core';
import { BaseComponent } from '@shared/bases/base.component';

@Component({
  selector: 'gateway-menu-list-item',
  templateUrl: './menu-list-item.component.html',
  styleUrls: ['menu-list-item.component.scss'],
})
export class MenuListItemComponent extends BaseComponent {
  @Input() label = '';
  @Input() icon = '';
  @Input() iconOnly = false;

  constructor() {
    super();
  }
}
