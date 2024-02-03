import {Component, EventEmitter, Input, OnChanges, OnInit, Output, SimpleChanges} from '@angular/core';
import {BaseComponent} from '@shared/bases/base.component';

@Component({
    selector: 'gateway-menu-group-list-item',
    templateUrl: './menu-group-list-item.component.html',
    styleUrls: ['menu-group-list-item.component.scss']
})
export class MenuGroupListItemComponent extends BaseComponent implements OnInit, OnChanges {
  @Input() title: string = '';
  @Input() accordion: boolean = true;
  @Input() accordionIcon: string = '';
  @Input() isMenuSlim: boolean = false;
  @Output() accordionToggled = new EventEmitter<'closed' | 'opened'>();

  isClosed: boolean = false;
  hasHeader: boolean = false;
  isAccordionArrowVisible: boolean = false;

  constructor() {
        super();
  }

  ngOnInit(): void {
    this.onMenuGroupMouseLeave(); // Call this function to reset the icon at init
  }

  onToggleMenuGroupList($event: MouseEvent): void {
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
