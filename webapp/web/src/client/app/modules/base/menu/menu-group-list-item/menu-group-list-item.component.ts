import {Component, Input} from '@angular/core';
import {BaseComponent} from '@shared/bases/base.component';

@Component({
    selector: 'gateway-menu-group-list-item',
    templateUrl: './menu-group-list-item.component.html',
    styleUrls: ['menu-group-list-item.component.scss']
})
export class MenuGroupListItemComponent extends BaseComponent {
  @Input() title: string = '';
  @Input() accordion: boolean = true;

  isClosed: boolean = false;

  constructor() {
        super();
  }

  onToggleMenuGroupList($event: MouseEvent): void {
      if (this.accordion) {
          this.isClosed = !this.isClosed;
      }
  }
}
