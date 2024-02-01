import {Injectable} from '@angular/core';
import {BehaviorSubject, Observable} from 'rxjs';
import {map} from "rxjs/operators";

import {WebSession} from "@shared/models/web-session.model";
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

  private webSessionCurrentTabIndexSubject: BehaviorSubject<number> = new BehaviorSubject(0);
  private webSessionCurrentTabIndex$: Observable<number> = this.webSessionCurrentTabIndexSubject.asObservable();

  constructor(private dynamicComponentService: DynamicComponentService) {}

  public get numberOfActiveSessions() {
    return this.webSessionDataSubject.getValue().length - SESSIONS_MENU_OFFSET;
  }

  addSession(newSession: WebSession<any, any>): void {
    newSession.tabIndex = this.webSessionDataSubject.getValue().length;
    const currentSessions = this.webSessionDataSubject.value;
    const updatedSessions = [...currentSessions, newSession];
    this.webSessionDataSubject.next(updatedSessions);
    this.setWebSessionTabIndexToLastCreated(newSession.tabIndex);
  }

  updateSession(tabIndex: number, newSession: WebSession<any, any>): void {
    newSession.tabIndex = tabIndex;

    this.removeSession(tabIndex).then(() => {
      this.addSession(newSession);
      }
    )
  }

  async removeSession(tabIndexToRemove?: number): Promise<void> {
    await this.destroyWebSessionComponentRef(tabIndexToRemove);

    const currentSessions = this.webSessionDataSubject.value;
    const filteredSessions = currentSessions.filter(session => session.tabIndex !== tabIndexToRemove);

    const updatedSessions = filteredSessions.map(session => {
      if (session.tabIndex && session.tabIndex > tabIndexToRemove) {
        return session.cloneWithUpdatedTabIndex(session.tabIndex - 1);
      }
      return session;
    });

    this.webSessionDataSubject.next(updatedSessions);
    this.setWebSessionCurrentIndex(this.NEW_SESSION_IDX);
  }

  async updateWebSessionIcon(tabIndex: number, icon: string): Promise<void> {
    const currentSessions = this.webSessionDataSubject.value;
    const index: number = currentSessions.findIndex(session => session.tabIndex === tabIndex);
    const webSession: WebSession<any, any> = currentSessions[index];
    webSession.icon = icon;

    if (index !== -1) {
      currentSessions[index] = webSession;
      this.webSessionDataSubject.next(currentSessions);
    } else {
      console.error('Web Session not found.')
    }
  }

  async destroyWebSessionComponentRef(indexToRemove: number): Promise<void> {
    try {
      const webSessionToDestroy = await this.getWebSession(indexToRemove);

      if (this.isSessionValid(webSessionToDestroy)) {
        this.dynamicComponentService.destroyComponent(webSessionToDestroy.componentRef);
      } else {
        console.warn('Invalid or non-existent session to destroy:', indexToRemove);
      }
    } catch (error) {
      console.error('Error destroying web session:', error);
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

  async getWebSession(indexOfWebSession: number): Promise<WebSession<any, any>> {
    const currentWebSessions = this.webSessionDataSubject.value;
    const session = currentWebSessions.filter(session => session.tabIndex === indexOfWebSession);

    if (session.length === 0) {
      return null
    }
    return session[0];
  }

  getWebSessionSnapshot(): WebSession<any, any>[] {
    return this.webSessionDataSubject.getValue();
  }

  setWebSessionCurrentIndex(index: number): void {
    this.webSessionCurrentTabIndexSubject.next(index);
  }

  getWebSessionCurrentIndex(): Observable<number> {
    return this.webSessionCurrentTabIndex$;
  }

  getWebSessionCurrentIndexSnapshot(): number {
    return this.webSessionCurrentTabIndexSubject.getValue();
  }

  setupNewWebSession(): void {
    this.webSessionCurrentTabIndexSubject.next(this.NEW_SESSION_IDX);
  }

  setWebSessionTabIndexToLastCreated(tabIndex?: number): void {
    if (this.webSessionDataSubject.getValue().length === 0) {
      this.setWebSessionCurrentIndex(0);
      return;
    }

    const lastSessionTabIndex: number = tabIndex;
    this.setWebSessionCurrentIndex(lastSessionTabIndex);
  }

  hasActiveWebSessions(): boolean {
    return this.numberOfActiveSessions > 0;
  }

  private isSessionValid(session) {
    return session && session.componentRef
  }
}
