import {Injectable} from '@angular/core';
import {BehaviorSubject, Observable} from 'rxjs';
import {WebSession} from "@shared/models/web-session.model";


@Injectable()
export class MainMenuService {
  isVisible: BehaviorSubject<boolean> = new BehaviorSubject(true);
  isCollapsed: BehaviorSubject<boolean> = new BehaviorSubject(true);


  private mainMenuDataSubject: BehaviorSubject<WebSession<any, any>[]> = new BehaviorSubject<WebSession<any, any>[]>([]);
  public mainMenuData$: Observable<WebSession<any, any>[]> = this.mainMenuDataSubject.asObservable();

  toggle():void {
    this.isVisible.next(!this.isVisible.getValue());
  }

  show():void {
    this.isVisible.next(true);
  }

  hide():void {
    this.isVisible.next(false);
  }

  collapse():void {
    this.isCollapsed.next(true);
  }

  expand():void {
    this.isCollapsed.next(false);
  }
}
