import { Component, Input } from '@angular/core';
import { BaseComponent } from '@shared/bases/base.component';
import { RouterMenuItem } from '../model/router-menu-item.model';

@Component({
  standalone: false,
  selector: 'gateway-menu-list-item',
  templateUrl: './menu-list-item.component.html',
  styleUrls: ['menu-list-item.component.scss'],
})
export class MenuListItemComponent extends BaseComponent {
  @Input() label = '';
  @Input() icon = '';
  @Input() iconOnly = false;
  @Input() item?: RouterMenuItem;

  constructor() {
    super();
  }

  onClick(): void {
    if (!this.item) {
      throw new Error('menu list item action is not configured');
    }

    if (this.item.blockClickSelected && this.item.selected) {
      return;
    }

    this.item.executeAction();
  }
}
