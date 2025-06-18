import { Injectable } from '@angular/core';
import { SessionType, WebSession } from '@shared/models/web-session.model';
import { BehaviorSubject } from 'rxjs';

@Injectable()
export class MainMenuService {
  isVisible: BehaviorSubject<boolean> = new BehaviorSubject(true);
  isCollapsed: BehaviorSubject<boolean> = new BehaviorSubject(true);

  private mainMenuDataSubject = new BehaviorSubject<WebSession<SessionType>[]>([]);
  public mainMenuData$ = this.mainMenuDataSubject.asObservable();

  toggle(): void {
    this.isVisible.next(!this.isVisible.getValue());
  }

  show(): void {
    this.isVisible.next(true);
  }

  hide(): void {
    this.isVisible.next(false);
  }

  collapse(): void {
    this.isCollapsed.next(true);
  }

  expand(): void {
    this.isCollapsed.next(false);
  }
}
