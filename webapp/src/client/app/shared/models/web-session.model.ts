import {ComponentRef, Type} from "@angular/core";
import { v4 as uuidv4 } from 'uuid';

import {RdpFormComponent} from "@gateway/modules/web-client/rdp/form/rdp-form.component";
import {WebClientRdpComponent} from "@gateway/modules/web-client/rdp/web-client-rdp.component";
import {ComponentStatus} from "@shared/models/component-status.model";
import {DesktopSize} from "@devolutions/iron-remote-gui";

export type WebSessionComponentType = Type<RdpFormComponent> | Type<WebClientRdpComponent>;

export class WebSession<WebSessionComponentType, TData> {
  public static readonly TOOLBAR_SIZE: number = 44;

  public id: string;
  public sessionId: string;
  public name: string = '';
  public component: WebSessionComponentType;
  public componentRef: ComponentRef<any>;
  public tabIndex?: number;
  public data?: TData;
  public icon?: string = '';
  public status: ComponentStatus;
  public desktopSize: DesktopSize;

  constructor(
    name: string,
    component: WebSessionComponentType,
    data?: TData,
    icon: string = '',
    tabIndex?: number,
    id: string = uuidv4(),
    sessionId: string = uuidv4(),
    status?: ComponentStatus,
    desktopSize?: DesktopSize
  ) {
    this.name = name;
    this.component = component;
    this.data = data;
    this.icon = icon;
    this.tabIndex = tabIndex;
    this.id = id;
    this.sessionId = sessionId;
    this.status = status;
    this.desktopSize = desktopSize;
  }

  updatedTabIndex(newTabIndex?: number): WebSession<WebSessionComponentType, TData>  {
    this.componentRef.instance.tabIndex = newTabIndex;
    this.tabIndex = newTabIndex;
    return this;
  }
}
