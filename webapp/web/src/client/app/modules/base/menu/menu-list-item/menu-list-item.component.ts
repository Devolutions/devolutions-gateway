import {Component, EventEmitter, Input, Output} from '@angular/core';
import {BaseComponent} from '@shared/bases/base.component';


@Component({
  selector: 'gateway-menu-list-item',
  templateUrl: './menu-list-item.component.html',
  styleUrls: ['menu-list-item.component.scss']
})
export class MenuListItemComponent extends BaseComponent {
  @Input() label: string = '';
  @Input() icon: string = '';
  @Input() disabled: boolean = false;
  @Input() id: string;
  @Input() blockClickSelected: boolean = false;
  @Input() iconOnly: boolean = false;
  @Input() selected: boolean = false;

  @Output() action: EventEmitter<MouseEvent> = new EventEmitter<MouseEvent>();

  constructor() {
    super();
  }
}
