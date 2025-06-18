import { Component, EventEmitter, Input, OnChanges, OnInit, Output, SimpleChanges } from '@angular/core';
import { BaseComponent } from '@shared/bases/base.component';

@Component({
  selector: 'gateway-menu-group-list-item',
  templateUrl: './menu-group-list-item.component.html',
  styleUrls: ['menu-group-list-item.component.scss'],
})
export class MenuGroupListItemComponent extends BaseComponent implements OnInit, OnChanges {
  @Input() title = '';
  @Input() accordion = true;
  @Input() accordionIcon = '';
  @Input() isMenuSlim = false;
  @Output() accordionToggled = new EventEmitter<'closed' | 'opened'>();

  isClosed = false;
  hasHeader = false;
  isAccordionArrowVisible = false;

  constructor() {
    super();
  }

  ngOnInit(): void {
    this.onMenuGroupMouseLeave(); // Call this function to reset the icon at init
  }

  onToggleMenuGroupList(_$event: MouseEvent): void {
    if (this.accordion) {
      this.isClosed = !this.isClosed;
      if (this.isClosed) {
        // this.closed.emit();
        this.accordionToggled.emit('closed');
      } else {
        this.accordionToggled.emit('opened');
        // this.opened.emit();
      }
    }
  }

  ngOnChanges(changes: SimpleChanges): void {
    if (changes.title || changes.accordion) {
      this.hasHeader = !!this.accordion || !!this.title;
    }
  }

  onMenuGroupMouseOver() {
    this.isAccordionArrowVisible = true;
  }

  onMenuGroupMouseLeave() {
    this.isAccordionArrowVisible = !this.accordionIcon;
  }
}
