import {ComponentRef, Injectable} from '@angular/core';
import {BehaviorSubject, Observable} from 'rxjs';
import {map} from "rxjs/operators";

import {WebSession} from "@shared/models/web-session.model";
import {DynamicComponentService} from "@shared/services/dynamic-component.service";
import {DesktopSize} from "@devolutions/iron-remote-gui";

// Offset is used to skip the first item in menu -- which is the create new session form.
// KAH Jan 2024
export const SESSIONS_MENU_OFFSET: number = 1;

@Injectable({
  providedIn: 'root',
})
export class WebSessionService {

  private NEW_SESSION_IDX: number = 0;
  private webSessionDataSubject: BehaviorSubject<WebSession<any, any>[]>;
  private webSessionData$: Observable<WebSession<any, any>[]>;

  private webSessionCurrentTabIndexSubject: BehaviorSubject<number>;
  private webSessionCurrentTabIndex$: Observable<number>;

  private webSessionScreenSizeSubject: BehaviorSubject<DesktopSize>;
  private webSessionScreenSizeIndex$: Observable<DesktopSize>;

  constructor(private dynamicComponentService: DynamicComponentService) {
    this.initializeWebSessionService();
  }

  public get numberOfActiveSessions(): number {
    return this.webSessionDataSubject.getValue().length - SESSIONS_MENU_OFFSET;
  }

  addSession(newSession: WebSession<any, any>): void {
    newSession.tabIndex = this.webSessionDataSubject.getValue().length;
    const currentSessions = this.webSessionDataSubject.value;
    const updatedSessions = [...currentSessions, newSession];
    this.webSessionDataSubject.next(updatedSessions);
    this.setWebSessionTabIndexToLastCreated(newSession.tabIndex);
  }

  updateSession(updatedWebSession: WebSession<any, any>): void {
    const currentSessions = this.webSessionDataSubject.value;
    const index: number = currentSessions.findIndex(webSession => webSession.id === updatedWebSession.id);

    if (index !== -1) {
      updatedWebSession.tabIndex = currentSessions[index].tabIndex;
      currentSessions[index] = updatedWebSession;

      this.webSessionDataSubject.next(currentSessions);
      this.setWebSessionTabIndexToLastCreated(updatedWebSession.tabIndex);
    } else {
      console.error('Web Session not found.')
    }
  }

  async removeSession(webSessionIdToRemove: string): Promise<void> {
    await this.destroyWebSessionComponentRef(webSessionIdToRemove);

    const currentSessions = this.webSessionDataSubject.value;
    const filteredSessions = currentSessions.
      filter(webSession => webSession.id !== webSessionIdToRemove);

    const sessionToRemove = await this.getWebSession(webSessionIdToRemove);
    const updatedSessions = filteredSessions.map(session => {
      if (session.tabIndex && session.tabIndex > sessionToRemove.tabIndex) {
        return session.updatedTabIndex(session.tabIndex - 1);
      }
      return session;
    });

    this.webSessionDataSubject.next(updatedSessions);
    this.setWebSessionCurrentIndex(this.NEW_SESSION_IDX);
  }

  async updateWebSessionIcon(updateWebSessionId: string, icon: string): Promise<void> {
    const currentSessions = this.webSessionDataSubject.value;
    const index: number = currentSessions.findIndex(session => session.id === updateWebSessionId);
    const webSession: WebSession<any, any> = currentSessions[index];
    webSession.icon = icon;

    if (index !== -1) {
      currentSessions[index] = webSession;
      this.webSessionDataSubject.next(currentSessions);
    } else {
      console.error('Web Session not found.')
    }
  }

  async destroyWebSessionComponentRef(webSessionId: string): Promise<void> {
    try {
      const webSessionToDestroy = await this.getWebSession(webSessionId);

      if (this.isWebSessionValid(webSessionToDestroy)) {
        this.dynamicComponentService.destroyComponent(webSessionToDestroy.componentRef);
      } else {
        console.warn('Invalid or non-existent session to destroy:', webSessionId);
      }
    } catch (error) {
      console.error('Error destroying web session:', error);
    }
  }

  cleanupWebSessionService(): void {
    this.webSessionDataSubject.getValue().forEach(session => {
      if (session.componentRef) {
        this.dynamicComponentService.destroyComponent(session.componentRef);
      }
    });

    this.webSessionDataSubject.complete();
    this.webSessionCurrentTabIndexSubject.complete();
    this.webSessionScreenSizeSubject.complete();

    this.initializeWebSessionService();
  }

  getAllWebSessions(): Observable<WebSession<any, any>[]> {
    return this.webSessionData$;
  }

  getMenuWebSessions(): Observable<WebSession<any, any>[]> {
    return this.webSessionData$.pipe(
        map(array => array.slice(SESSIONS_MENU_OFFSET))
    );
  }

  async getWebSession(webSessionId: string): Promise<WebSession<any, any>> {
    const currentWebSessions = this.webSessionDataSubject.value;
    const webSession = currentWebSessions.
      filter(webSession => webSession.id === webSessionId);

    if (webSession.length === 0) {
      return null
    }
    return webSession[0];
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

  setWebSessionScreenSize(desktopSize: DesktopSize): void {
    this.webSessionScreenSizeSubject.next(desktopSize);
  }

  getWebSessionScreenSize(): Observable<DesktopSize> {
    return this.webSessionScreenSizeIndex$;
  }

  getWebSessionScreenSizeSnapshot(): DesktopSize {
    return this.webSessionScreenSizeSubject.getValue();
  }

  setWebSessionTabIndexToLastCreated(tabIndex?: number): void {
    if (this.webSessionDataSubject.getValue().length === 0) {
      this.setWebSessionCurrentIndex(0);
      return;
    }

    this.setWebSessionCurrentIndex(tabIndex);
  }

  hasActiveWebSessions(): boolean {
    return this.numberOfActiveSessions > 0;
  }

  private initializeWebSessionService(): void {
    this.webSessionDataSubject = new BehaviorSubject<WebSession<any, any>[]>([]);
    this.webSessionData$ = this.webSessionDataSubject.asObservable();

    this.webSessionCurrentTabIndexSubject = new BehaviorSubject(0);
    this.webSessionCurrentTabIndex$ = this.webSessionCurrentTabIndexSubject.asObservable();

    this.webSessionScreenSizeSubject = new BehaviorSubject(undefined);
    this.webSessionScreenSizeIndex$ = this.webSessionScreenSizeSubject.asObservable();
  }

  private isWebSessionValid(WebSession: WebSession<any, any>):ComponentRef<any> {
    return WebSession && WebSession.componentRef
  }
}
