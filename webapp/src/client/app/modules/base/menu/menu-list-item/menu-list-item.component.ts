import { CommonModule } from '@angular/common';
import { Component, Input } from '@angular/core';
import { BaseComponent } from '@shared/bases/base.component';
import { TooltipModule } from 'primeng/tooltip';

@Component({
  selector: 'gateway-menu-list-item',
  templateUrl: './menu-list-item.component.html',
  styleUrls: ['menu-list-item.component.scss'],
  standalone: true,
  imports: [CommonModule, TooltipModule],
})
export class MenuListItemComponent extends BaseComponent {
  @Input() label = '';
  @Input() icon = '';
  @Input() iconOnly = false;

  constructor() {
    super();
  }
}
