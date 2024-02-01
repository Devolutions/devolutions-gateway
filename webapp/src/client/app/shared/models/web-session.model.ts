import {ComponentRef, Type} from "@angular/core";
import { Guid } from 'guid-typescript';

import {RdpFormComponent} from "@gateway/modules/web-client/rdp/form/rdp-form.component";
import {WebClientRdpComponent} from "@gateway/modules/web-client/rdp/web-client-rdp.component";
import {DesktopSize} from "@shared/models/desktop-size";
import {ScreenSize} from "@shared/enums/screen-size.enum";
import {ComponentStatus} from "@shared/models/component-status.model";

export type WebSessionComponentType = Type<RdpFormComponent> | Type<WebClientRdpComponent>;

export class WebSession<WebSessionComponentType, TData> {
  public id: Guid;
  public sessionId: number;
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
    id: Guid = Guid.create(),
    sessionId?: number,
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
    this.desktopSize = desktopSize ?? this.getScreenSize(data);
  }

  cloneWithUpdatedTabIndex(newTabIndex?: number): WebSession<WebSessionComponentType, TData> {
    return new WebSession(
      this.name,
      this.component,
      this.data,
      this.icon,
      newTabIndex,
      this.id,
      this.sessionId,
      this.status,
      this.desktopSize
    );
  }

  private getScreenSize(submittedFormData: any): DesktopSize | null {
    if (!submittedFormData?.screenSize) {
      return null;
    }
    let enumSize: ScreenSize = submittedFormData.screenSize;
    if (enumSize >= 2 && enumSize <= 20) {
      const rawSize = ScreenSize[enumSize]?.substring(1, ScreenSize[enumSize].length)?.split('x');
      return rawSize.length > 1 ? { width: parseInt(rawSize[0]), height: parseInt(rawSize[1]) } : null;
    } else if (enumSize === ScreenSize.Custom) {
      return submittedFormData.customWidth && submittedFormData.customHeight ? { width: submittedFormData.customWidth, height: submittedFormData.customHeight } : null;
    }
    return null;
  }
}
