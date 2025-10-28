import { Injectable, Type } from '@angular/core';
import { FormGroup } from '@angular/forms';
import { DVL_WARNING_ICON, ProtocolIconMap } from '@gateway/app.constants';
import { WebClientArdComponent } from '@gateway/modules/web-client/ard/web-client-ard.component';
import { WebClientRdpComponent } from '@gateway/modules/web-client/rdp/web-client-rdp.component';
import { WebClientSshComponent } from '@gateway/modules/web-client/ssh/web-client-ssh.component';
import { WebClientTelnetComponent } from '@gateway/modules/web-client/telnet/web-client-telnet.component';
import { WebClientVncComponent } from '@gateway/modules/web-client/vnc/web-client-vnc.component';
import { Protocol } from '@shared/enums/web-client-protocol.enum';
import { AutoCompleteInput } from '@shared/interfaces/forms.interfaces';
import { DesktopSize } from '@shared/models/desktop-size';
import { WebSession } from '@shared/models/web-session.model';
import { DynamicComponentService } from '@shared/services/dynamic-component.service';
import { BehaviorSubject, Observable, of } from 'rxjs';
import { map } from 'rxjs/operators';
import {
  CanSendTerminateSessionCmd,
  ComponentForSession,
  ConnectionSessionType,
  SessionType,
} from './../models/web-session.model';

// Offset is used to skip the first item in menu -- which is the create new session form.
// KAH Jan 2024
export const SESSIONS_MENU_OFFSET: number = 1;

export interface ExtraSessionParameter {
  sshPrivateKey?: string;
}

@Injectable({
  providedIn: 'root',
})
export class WebSessionService {
  private NEW_SESSION_IDX = 0;
  private webSessionDataSubject: BehaviorSubject<WebSession<SessionType>[]>;
  private webSessionData$: Observable<WebSession<SessionType>[]>;

  private webSessionCurrentTabIndexSubject: BehaviorSubject<number>;
  private webSessionCurrentTabIndex$: Observable<number>;

  private webSessionScreenSizeSubject: BehaviorSubject<DesktopSize>;
  private webSessionScreenSizeIndex$: Observable<DesktopSize>;

  private protocolComponentMap = {
    [Protocol.RDP]: WebClientRdpComponent,
    [Protocol.Telnet]: WebClientTelnetComponent,
    [Protocol.SSH]: WebClientSshComponent,
    [Protocol.VNC]: WebClientVncComponent,
    [Protocol.ARD]: WebClientArdComponent,
  };

  constructor(private dynamicComponentService: DynamicComponentService) {
    this.initializeWebSessionService();
  }

  public get numberOfActiveSessions(): number {
    return this.webSessionDataSubject.getValue().length - SESSIONS_MENU_OFFSET;
  }

  public get numberOfAllSessions(): number {
    return this.webSessionDataSubject.getValue().length;
  }

  createWebSession(
    form: FormGroup,
    protocol: Protocol, // Dynamically infer the type from the map
    extraData: ExtraSessionParameter,
  ): Observable<WebSession<ConnectionSessionType>> {
    // Use the map to infer return type
    const submittedData = form.value;
    submittedData.hostname = this.processHostname(submittedData.autoComplete);

    const sessionComponent = this.protocolComponentMap[protocol];
    const iconName: string = ProtocolIconMap[protocol];

    if (!sessionComponent) {
      console.error(`Creating session, unsupported protocol: ${protocol}`);
      return of(null);
    }

    submittedData.extraData = extraData;

    // WebSession's type now corresponds to the mapped component type
    const webSession = new WebSession<ConnectionSessionType>(
      submittedData.hostname,
      // use a type assertion to help TypeScript recognize the type match
      sessionComponent as Type<ComponentForSession<ConnectionSessionType>>,
      submittedData,
      iconName,
    );
    return of(webSession);
  }

  addSession(newSession: WebSession<SessionType>): void {
    newSession.tabIndex = this.webSessionDataSubject.getValue().length;
    const currentSessions = this.webSessionDataSubject.value;
    const updatedSessions = [...currentSessions, newSession];
    this.webSessionDataSubject.next(updatedSessions);
    this.setWebSessionTabIndexToLastCreated(newSession.tabIndex);
  }

  updateSession(updatedWebSession: WebSession<SessionType>): void {
    const currentSessions = this.webSessionDataSubject.value;
    const index: number = currentSessions.findIndex((webSession) => webSession.id === updatedWebSession.id);

    if (index !== -1) {
      updatedWebSession.tabIndex = currentSessions[index].tabIndex;
      currentSessions[index] = updatedWebSession;

      this.webSessionDataSubject.next(currentSessions);
      this.setWebSessionTabIndexToLastCreated(updatedWebSession.tabIndex);
    } else {
      console.error('Web Session not found.');
    }
  }

  async removeSession(webSessionIdToRemove: string): Promise<void> {
    await this.destroyWebSessionComponentRef(webSessionIdToRemove);

    const currentSessions = this.webSessionDataSubject.value;
    const filteredSessions = currentSessions.filter((webSession) => webSession.id !== webSessionIdToRemove);

    const sessionToRemove = await this.getWebSession(webSessionIdToRemove);
    const updatedSessions = filteredSessions.map((session) => {
      if (session.tabIndex && session.tabIndex > sessionToRemove.tabIndex) {
        return session.updatedTabIndex(session.tabIndex - 1);
      }
      return session;
    });

    this.webSessionDataSubject.next(updatedSessions);
    this.setWebSessionCurrentIndex(this.NEW_SESSION_IDX);
  }

  //For translation ConnectionHasBeenTerminatedEllipsis
  async updateWebSessionIcon(updateWebSessionId: string, icon: string): Promise<void> {
    const currentSessions = this.webSessionDataSubject.value;
    const index: number = currentSessions.findIndex((session) => session.id === updateWebSessionId);
    const webSession = currentSessions[index];

    if (index !== -1) {
      webSession.icon = icon;
      if (icon === DVL_WARNING_ICON) {
        webSession.iconTooltip = 'Connection has been terminated.';
      }

      currentSessions[index] = webSession;
      this.webSessionDataSubject.next(currentSessions);
    } else {
      console.warn('Web Session not found.');
    }
  }

  async destroyWebSessionComponentRef(webSessionId: string): Promise<void> {
    try {
      const webSessionToDestroy = await this.getWebSession(webSessionId);

      if (this.isWebSessionValid(webSessionToDestroy)) {
        await this.terminateSession(webSessionToDestroy);
        this.dynamicComponentService.destroyComponent(webSessionToDestroy.componentRef);
      } else {
        console.warn('Invalid or non-existent session to destroy:', webSessionId);
      }
    } catch (error) {
      console.error('Error destroying web session:', error);
    }
  }

  async cleanupWebSessionService(): Promise<void> {
    for (const session of this.webSessionDataSubject.getValue()) {
      if (session.componentRef) {
        await this.terminateSession(session);
        this.dynamicComponentService.destroyComponent(session.componentRef);
      }
    }

    this.completeSubjects();
    this.initializeWebSessionService();
  }

  getAllWebSessions() {
    return this.webSessionData$;
  }

  getMenuWebSessions() {
    return this.webSessionData$.pipe(map((array) => array.slice(SESSIONS_MENU_OFFSET)));
  }

  async getWebSession(webSessionId: string) {
    const currentWebSessions = this.webSessionDataSubject.value;
    const webSession = currentWebSessions.filter((webSession) => webSession.id === webSessionId);

    if (webSession.length === 0) {
      return null;
    }
    return webSession[0];
  }

  getWebSessionSnapshot() {
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

  private completeSubjects(): void {
    this.webSessionDataSubject.complete();
    this.webSessionCurrentTabIndexSubject.complete();
    this.webSessionScreenSizeSubject.complete();
  }

  private async terminateSession<T extends SessionType & Partial<CanSendTerminateSessionCmd>>(
    session: WebSession<T>,
  ): Promise<void> {
    if (typeof session.componentRef.instance.sendTerminateSessionCmd === 'function') {
      session.componentRef.instance.sendTerminateSessionCmd();
    }
  }

  private initializeWebSessionService(): void {
    this.webSessionDataSubject = new BehaviorSubject<WebSession<ConnectionSessionType>[]>([]);
    this.webSessionData$ = this.webSessionDataSubject.asObservable();

    this.webSessionCurrentTabIndexSubject = new BehaviorSubject(0);
    this.webSessionCurrentTabIndex$ = this.webSessionCurrentTabIndexSubject.asObservable();

    this.webSessionScreenSizeSubject = new BehaviorSubject(undefined);
    this.webSessionScreenSizeIndex$ = this.webSessionScreenSizeSubject.asObservable();
  }

  private isWebSessionValid(WebSession: WebSession<SessionType>) {
    return WebSession?.componentRef;
  }

  private processHostname(autoCompleteInput: AutoCompleteInput): string {
    if (typeof autoCompleteInput === 'string') {
      return autoCompleteInput;
    }

    return autoCompleteInput?.hostname || '';
  }
}
