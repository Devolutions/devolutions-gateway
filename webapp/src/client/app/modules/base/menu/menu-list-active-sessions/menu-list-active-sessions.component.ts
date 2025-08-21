import { Component, Input, OnInit } from '@angular/core';
import { BaseComponent } from '@shared/bases/base.component';
import { SessionType, WebSession } from '@shared/models/web-session.model';
import { WebSessionService } from '@shared/services/web-session.service';
import { takeUntil } from 'rxjs/operators';

@Component({
  selector: 'gateway-menu-list-active-sessions',
  templateUrl: './menu-list-active-sessions.component.html',
  styleUrls: ['menu-list-active-sessions.component.scss'],
})
export class MenuListActiveSessionsComponent extends BaseComponent implements OnInit {
  // disables the menu item
  @Input() disabled = false;

  // indicates user is currently on the screen for the menu item
  @Input() selected = false;
  @Input() isMenuSlim = false;

  activeWebSessions: WebSession<SessionType>[] = [];
  activeWebSessionIndex = 0;

  constructor(private webSessionService: WebSessionService) {
    super();
  }

  ngOnInit(): void {
    this.subscribeToWebSessionsUpdates();
    this.subscribeToWebSessionsActiveIndex();
  }

  onMenuListItemClick(event: MouseEvent, webSession: WebSession<SessionType>): void {
    if (this.selected || this.disabled) {
      event.preventDefault();
      event.stopPropagation();
      return;
    }
    this.activeWebSessionIndex = webSession.tabIndex;
    this.selectTab(webSession.tabIndex);
  }

  onCloseButtonClick(event: MouseEvent, webSession: WebSession<SessionType>): void {
    event.stopPropagation();
    void this.webSessionService.removeSession(webSession.id);
  }

  private selectTab(tabIndex: number): void {
    this.webSessionService.setWebSessionCurrentIndex(tabIndex);
  }

  private subscribeToWebSessionsUpdates(): void {
    this.webSessionService
      .getMenuWebSessions()
      .pipe(takeUntil(this.destroyed$))
      .subscribe({
        next: (tabs) => {
          this.activeWebSessions = tabs;
        },
        error: (e) => console.error(e),
      });
  }

  private subscribeToWebSessionsActiveIndex(): void {
    this.webSessionService
      .getWebSessionCurrentIndex()
      .pipe(takeUntil(this.destroyed$))
      .subscribe({
        next: (activeIndex: number) => {
          this.activeWebSessionIndex = activeIndex;
        },
        error: (e) => console.error(e),
      });
  }
}
