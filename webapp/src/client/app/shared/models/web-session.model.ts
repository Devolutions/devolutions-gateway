import { ComponentRef, ElementRef, Type } from '@angular/core';
import { WebClientArdComponent } from '@gateway/modules/web-client/ard/web-client-ard.component';
import { WebClientFormComponent } from '@gateway/modules/web-client/form/web-client-form.component';
import { WebClientRdpComponent } from '@gateway/modules/web-client/rdp/web-client-rdp.component';
import { WebClientSshComponent } from '@gateway/modules/web-client/ssh/web-client-ssh.component';
import { WebClientTelnetComponent } from '@gateway/modules/web-client/telnet/web-client-telnet.component';
import { WebClientVncComponent } from '@gateway/modules/web-client/vnc/web-client-vnc.component';
import { MainPanelComponent } from '@shared/components/main-panel/main-panel.component';
import { ComponentStatus } from '@shared/models/component-status.model';
import { DesktopSize } from '@shared/models/desktop-size';
import { v4 as uuidv4 } from 'uuid';
import { BaseComponent } from '../bases/base.component';
import {
  ArdFormDataInput,
  RdpFormDataInput,
  SSHFormDataInput,
  TelnetFormDataInput,
  VncFormDataInput,
} from '../interfaces/forms.interfaces';

export type WebSessionComponentType =
  | Type<WebClientTelnetComponent>
  | Type<WebClientSshComponent>
  | Type<WebClientRdpComponent>
  | Type<WebClientArdComponent>
  | Type<WebClientVncComponent>
  | Type<MainPanelComponent>
  | Type<WebClientFormComponent>;

export interface SessionDataTypeMap {
  WebClientFormComponent: never;
  MainPanelComponent: never;
  WebClientArdComponent: ArdFormDataInput;
  WebClientRdpComponent: RdpFormDataInput;
  WebClientSshComponent: SSHFormDataInput;
  WebClientTelnetComponent: TelnetFormDataInput;
  WebClientVncComponent: VncFormDataInput;
}

export interface SessionTypeMap {
  WebClientArdComponent: WebClientArdComponent;
  WebClientFormComponent: WebClientFormComponent;
  WebClientRdpComponent: WebClientRdpComponent;
  WebClientSshComponent: WebClientSshComponent;
  WebClientTelnetComponent: WebClientTelnetComponent;
  WebClientVncComponent: WebClientVncComponent;
  MainPanelComponent: MainPanelComponent;
}

export type DataForSession<T extends keyof SessionDataTypeMap> = SessionDataTypeMap[T];
export type ComponentForSession<T extends keyof SessionDataTypeMap> = SessionTypeMap[T];

export interface HasTabIndex {
  tabIndex?: number;
}

export abstract class BaseSessionComponent extends BaseComponent implements HasTabIndex {
  tabIndex?: number;
  webSessionId: string;
  sessionsContainerElement: ElementRef;
}

export interface CanSendTerminateSessionCmd {
  sendTerminateSessionCmd(): void;
}

export type SessionType = keyof SessionDataTypeMap;
export type ConnectionSessionType = keyof Omit<SessionDataTypeMap, 'WebClientFormComponent' | 'MainPanelComponent'>;

export class WebSession<T extends keyof SessionDataTypeMap> {
  public static readonly TOOLBAR_SIZE: number = 44;

  public id: string;
  public sessionId: string;
  public name = '';
  public component: Type<ComponentForSession<T>>;
  public componentRef: ComponentRef<ComponentForSession<T> & Partial<CanSendTerminateSessionCmd>>;
  public tabIndex?: number;
  public data?: DataForSession<T>;
  public icon?: string = '';
  public iconTooltip?: string = '';
  public status: ComponentStatus;
  public desktopSize: DesktopSize;

  constructor(
    name: string,
    component: Type<ComponentForSession<T>>,
    data?: DataForSession<T>,
    icon = '',
    tabIndex?: number,
    id: string = uuidv4(),
    sessionId: string = uuidv4(),
    status?: ComponentStatus,
    desktopSize?: DesktopSize,
  ) {
    this.name = name;
    this.component = component;
    this.data = data;
    this.icon = icon;
    this.iconTooltip = name;
    this.tabIndex = tabIndex;
    this.id = id;
    this.sessionId = sessionId;
    this.status = status;
    this.desktopSize = desktopSize;
  }

  updatedTabIndex(newTabIndex?: number): WebSession<T> {
    this.componentRef.instance.tabIndex = newTabIndex;
    this.tabIndex = newTabIndex;
    return this;
  }
}
