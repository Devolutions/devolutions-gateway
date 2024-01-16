import {Injectable} from '@angular/core';
import {BehaviorSubject, Observable} from 'rxjs';
import {WebSession} from "@shared/models/web-session.model";
import {map} from "rxjs/operators";
import {DynamicComponentService} from "@shared/services/dynamic-component.service";

// Offset is used to skip the first item in menu -- which is the create new session form.
// KAH Jan 2024
export const SESSIONS_MENU_OFFSET: number = 1;

@Injectable({
  providedIn: 'root',
})
export class WebSessionService {

  private NEW_SESSION_IDX: number = 0;
  private webSessionDataSubject: BehaviorSubject<WebSession<any, any>[]> = new BehaviorSubject<WebSession<any, any>[]>([]);
  private webSessionData$: Observable<WebSession<any, any>[]> = this.webSessionDataSubject.asObservable();

  private webSessionCurrentIndexSubject: BehaviorSubject<number> = new BehaviorSubject(0);
  private webSessionCurrentIndex$: Observable<number> = this.webSessionCurrentIndexSubject.asObservable();

  constructor(private dynamicComponentService: DynamicComponentService) {}

  addSession(newSession: WebSession<any, any>): void {
    const currentSessions = this.webSessionDataSubject.value;
    const updatedSessions = [...currentSessions, newSession];
    this.webSessionDataSubject.next(updatedSessions);
    this.setWebSessionIndexToLastCreated();
  }

  async removeSession(indexToRemove?: number): Promise<void> {
    if (typeof indexToRemove === 'undefined') {
      indexToRemove = this.webSessionCurrentIndexSubject.getValue();
    }

    this.destroyWebSessionComponentRef(indexToRemove);
    const currentWebSessions = this.webSessionDataSubject.getValue();

    if (indexToRemove >= 0 && indexToRemove < currentWebSessions.length) {
      const updatedSessions = currentWebSessions.filter((_, index) => index !== indexToRemove);
      this.webSessionDataSubject.next(updatedSessions);

      this.setWebSessionCurrentIndex(indexToRemove-1);
    } else {
      throw new Error('Remove Session: Index is out of bounds.');
    }
  }

  destroyWebSessionComponentRef(indexToRemove: number): void {
    const webSessionToDestroy = this.getWebSession(indexToRemove);
    if (webSessionToDestroy && webSessionToDestroy.componentRef) {
      this.dynamicComponentService.destroyComponent(webSessionToDestroy.componentRef);
    }
  }

  getAllWebSessions(): Observable<WebSession<any, any>[]> {
    return this.webSessionData$;
  }

  getMenuWebSessions(): Observable<WebSession<any, any>[]> {
    return this.webSessionData$.pipe(
        map(array => array.slice(SESSIONS_MENU_OFFSET))
    );
  }

  getWebSession(indexOfWebSession?: number): WebSession<any, any> {
    if (!indexOfWebSession) {
      indexOfWebSession = this.getWebSessionCurrentIndexSnapshot();
    }

    const currentWebSessions = this.webSessionDataSubject.value;
    return currentWebSessions[indexOfWebSession] || null;
  }

  getWebSessionSnapshot(): WebSession<any, any>[] {
    return this.webSessionDataSubject.getValue();
  }

  setWebSessionCurrentIndex(index: number): void {
    this.webSessionCurrentIndexSubject.next(index);
  }

  getWebSessionCurrentIndex(): Observable<number> {
    return this.webSessionCurrentIndex$;
  }

  getWebSessionCurrentIndexSnapshot(): number {
    return this.webSessionCurrentIndexSubject.getValue();
  }

  setupNewWebSession(): void {
    this.webSessionCurrentIndexSubject.next(this.NEW_SESSION_IDX);
  }

  setWebSessionIndexToLastCreated(): void {
    if (this.webSessionDataSubject.getValue().length === 0) {
      this.setWebSessionCurrentIndex(0);
      return;
    }

    const lastSessionIndex: number = this.webSessionDataSubject.getValue().length - 1;
    this.setWebSessionCurrentIndex(lastSessionIndex);
  }
}
