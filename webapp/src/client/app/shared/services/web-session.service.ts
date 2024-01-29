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

  public get numberOfActiveSessions() {
    return this.webSessionDataSubject.getValue().length - SESSIONS_MENU_OFFSET;
  }

  addSession(newSession: WebSession<any, any>): void {
    newSession.tabIndex = this.webSessionDataSubject.getValue().length;
    const currentSessions = this.webSessionDataSubject.value;
    const updatedSessions = [...currentSessions, newSession];
    this.webSessionDataSubject.next(updatedSessions);
    this.setWebSessionIndexToLastCreated();
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
    const updatedSessions = currentSessions.filter(session => session.tabIndex !== tabIndexToRemove);
    this.webSessionDataSubject.next(updatedSessions);

    this.setWebSessionCurrentIndex(this.NEW_SESSION_IDX);
  }

  //TODO Fix bc tabIndex is in Web Session
  removeAllSessions(): void {
    // const currentWebSessions = this.webSessionDataSubject.getValue();
    // for (let i: number = currentWebSessions.length - 1; i >= 0; i--) {
    //   this.destroyWebSessionComponentRef(i);
    // }
    // this.webSessionDataSubject.next([]);
    // this.webSessionCurrentIndexSubject.next(0);
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

  hasActiveWebSessions(): boolean {
    return this.numberOfActiveSessions > 0;
  }

  private isSessionValid(session) {
    return session && session.componentRef
  }
}
