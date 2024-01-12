import {RdpFormComponent} from "@gateway/modules/web-client/rdp/form/rdp-form.component";
import {WebClientRdpComponent} from "@gateway/modules/web-client/rdp/web-client-rdp.component";
import {ComponentRef, Type} from "@angular/core";
import { Guid } from 'guid-typescript';
import {DesktopSize} from "@shared/models/desktop-size";

export type WebSessionComponentType = Type<RdpFormComponent> | Type<WebClientRdpComponent>;

export class WebSession<WebSessionComponentType, TData> {
  public id: Guid;
  public sessionId: number;
  public name: string = '';
  public component: WebSessionComponentType;
  public componentRef: ComponentRef<any>;
  public data?: TData;
  public icon?: string = '';
  public active: boolean;
  public desktopSize!: DesktopSize;

  constructor(name: string, component: WebSessionComponentType, data?: TData, icon?: string) {
    this.id = Guid.create();
    this.name = name;
    this.component = component;
    this.data = data;
    this.icon = icon;
  }
}
