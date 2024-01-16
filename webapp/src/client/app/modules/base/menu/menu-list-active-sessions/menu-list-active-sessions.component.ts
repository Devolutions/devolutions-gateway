import {Component, Input, OnInit} from '@angular/core';
import {BaseComponent} from '@shared/bases/base.component';
import {WebSession} from "@shared/models/web-session.model";
import {SESSIONS_MENU_OFFSET, WebSessionService} from "@shared/services/web-session.service";
import {noop} from "rxjs";
import {takeUntil} from "rxjs/operators";


@Component({
  selector: 'gateway-menu-list-active-sessions',
  templateUrl: './menu-list-active-sessions.component.html',
  styleUrls: ['menu-list-active-sessions.component.scss']
})
export class MenuListActiveSessionsComponent extends BaseComponent implements OnInit {
  // disables the menu item
  @Input() disabled: boolean = false;

  // indicates user is currently on the screen for the menu item
  @Input() selected: boolean = false;

  activeWebSessions: WebSession<any, any>[] = [];
  activeWebSessionIndex: number = 0;
  selectedMenuIndex: number = 0;

  constructor(private webSessionService: WebSessionService) {
    super();
  }

  ngOnInit(): void {
    this.subscribeToWebSessionsUpdates();
    this.subscribeToWebSessionsActiveIndex();
  }

  onMenuListItemClick(event: MouseEvent, index: number): void {
    if (this.selected || this.disabled) {
      event.preventDefault();
      event.stopPropagation();
      return;
    }
    this.selectedMenuIndex = index;
    this.selectTab(index)
  }

  onCloseButtonClick(event: MouseEvent, index: number): void {
    this.webSessionService.removeSession(this.adjustTabIndex(index)).then(noop);
  }

  private selectTab(tabIndex: any): void {
    this.webSessionService.setWebSessionCurrentIndex(this.adjustTabIndex(tabIndex));
  }

  private adjustTabIndex(index: number): number {
    return index + SESSIONS_MENU_OFFSET;
  }

  private adjustMenuIndex(index: number): number {
    return index - SESSIONS_MENU_OFFSET;
  }

  private subscribeToWebSessionsUpdates(): void {
    this.webSessionService.getMenuWebSessions().pipe(takeUntil(this.destroyed$)).subscribe({
      next: (tabs:WebSession<any, any>[]) => this.activeWebSessions = tabs,
      error: (e) => console.error(e),
      complete: () => console.info('complete')
    });
  }

  private subscribeToWebSessionsActiveIndex(): void {
    this.webSessionService.getWebSessionCurrentIndex().pipe(takeUntil(this.destroyed$)).subscribe({
      next: (activeIndex:number) => {
        this.activeWebSessionIndex = activeIndex;
        this.selectedMenuIndex = this.adjustMenuIndex(activeIndex);
      },
      error: (e) => console.error(e),
      complete: () => console.info('complete')
    });
  }
}
