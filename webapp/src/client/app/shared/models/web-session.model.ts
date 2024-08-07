import { ComponentRef, Type } from '@angular/core';
import { v4 as uuidv4 } from 'uuid';

import { DesktopSize } from '@devolutions/iron-remote-gui';
import { WebClientFormComponent } from '@gateway/modules/web-client/form/web-client-form.component';
import { WebClientRdpComponent } from '@gateway/modules/web-client/rdp/web-client-rdp.component';
import { WebClientSshComponent } from '@gateway/modules/web-client/ssh/web-client-ssh.component';
import { WebClientTelnetComponent } from '@gateway/modules/web-client/telnet/web-client-telnet.component';
import { ComponentStatus } from '@shared/models/component-status.model';

export type WebSessionComponentType =
  | Type<WebClientFormComponent>
  | Type<WebClientTelnetComponent>
  | Type<WebClientSshComponent>
  | Type<WebClientRdpComponent>;

export class WebSession<WebSessionComponentType, TData> {
  public static readonly TOOLBAR_SIZE: number = 44;

  public id: string;
  public sessionId: string;
  public name = '';
  public component: WebSessionComponentType;
  public componentRef: ComponentRef<any>;
  public tabIndex?: number;
  public data?: TData;
  public icon?: string = '';
  public iconTooltip?: string = '';
  public status: ComponentStatus;
  public desktopSize: DesktopSize;

  constructor(
    name: string,
    component: WebSessionComponentType,
    data?: TData,
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

  updatedTabIndex(newTabIndex?: number): WebSession<WebSessionComponentType, TData> {
    this.componentRef.instance.tabIndex = newTabIndex;
    this.tabIndex = newTabIndex;
    return this;
  }
}
