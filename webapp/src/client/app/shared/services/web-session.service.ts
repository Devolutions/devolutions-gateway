import {ComponentRef, Injectable} from '@angular/core';
import {BehaviorSubject, Observable, of} from 'rxjs';
import {map} from "rxjs/operators";
import {FormGroup} from "@angular/forms";

import {WebSession} from "@shared/models/web-session.model";
import {Protocol} from "@shared/enums/web-client-protocol.enum";
import {AutoCompleteInput} from "@shared/interfaces/forms.interfaces";
import {DynamicComponentService} from "@shared/services/dynamic-component.service";
import {DesktopSize} from "@devolutions/iron-remote-gui";
import {WebClientFormComponent} from "@gateway/modules/web-client/form/web-client-form.component";
import {WebClientRdpComponent} from "@gateway/modules/web-client/rdp/web-client-rdp.component";
import {WebClientTelnetComponent} from "@gateway/modules/web-client/telnet/web-client-telnet.component";
import {WebClientSshComponent} from "@gateway/modules/web-client/ssh/web-client-ssh.component";
import {WebClientVncComponent} from "@gateway/modules/web-client/vnc/web-client-vnc.component";
import {WebClientArdComponent} from "@gateway/modules/web-client/ard/web-client-ard.component";

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

  private protocolComponentMap = {
    [Protocol.RDP]: WebClientRdpComponent,
    [Protocol.Telnet]: WebClientTelnetComponent,
    [Protocol.SSH]: WebClientSshComponent,
    [Protocol.VNC]: WebClientVncComponent,
    [Protocol.ARD]: WebClientArdComponent,
  };

  private protocolIconMap = {
    [Protocol.RDP]: WebClientRdpComponent.DVL_RDP_ICON,
    [Protocol.Telnet]: WebClientTelnetComponent.DVL_TELNET_ICON,
    [Protocol.SSH]: WebClientSshComponent.DVL_SSH_ICON,
    [Protocol.VNC]: WebClientVncComponent.DVL_VNC_ICON,
    [Protocol.ARD]: WebClientArdComponent.DVL_ARD_ICON,
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

  createWebSession(form: FormGroup, protocol: Protocol): Observable<WebSession<any, any>> {
    const submittedData = form.value;
    submittedData.hostname = this.processHostname(submittedData.autoComplete);

    const sessionComponent = this.protocolComponentMap[protocol];
    const iconName: string = this.protocolIconMap[protocol];

    if (!sessionComponent) {
      console.error(`Creating session, unsupported protocol: ${protocol}`)
      return;
    }

    const webSession = new WebSession(
      submittedData.hostname,
      sessionComponent,
      submittedData,
      iconName
    );
    return of(webSession);
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

    if (index !== -1) {
      webSession.icon = icon;
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
        this.terminateSession(session);
        this.dynamicComponentService.destroyComponent(session.componentRef);
      }
    });

    this.completeSubjects();
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

  private completeSubjects(): void {
    this.webSessionDataSubject.complete();
    this.webSessionCurrentTabIndexSubject.complete();
    this.webSessionScreenSizeSubject.complete();
  }

  private terminateSession(session: WebSession<any, any>): void {
    if (typeof session.componentRef.instance.sendTerminateSessionCmd === 'function') {
      session.componentRef.instance.sendTerminateSessionCmd();
      console.warn(`Session for ${session.componentRef.instance.formData?.hostname || 'unknown host'} terminated.`);
    } else if (session.componentRef.componentType !== WebClientFormComponent) {
      console.warn(`Session for ${session.componentRef.instance.formData?.hostname || 'unknown host'} has no terminate command.`);
    }
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

  private processHostname(autoCompleteInput: AutoCompleteInput): string {
    if (typeof autoCompleteInput === 'string') {
      return autoCompleteInput;
    }

    return autoCompleteInput?.hostname || '';
  }
}
