import {RdpFormComponent} from "@gateway/modules/web-client/rdp/form/rdp-form.component";
import {WebClientRdpComponent} from "@gateway/modules/web-client/rdp/web-client-rdp.component";
import {ComponentRef, Type} from "@angular/core";
import { Guid } from 'guid-typescript';
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
  public desktopSize!: DesktopSize;

  constructor(name: string, component: WebSessionComponentType, data?: TData, icon?: string) {
    this.id = Guid.create();
    this.name = name;
    this.component = component;
    this.data = data;
    this.icon = icon;
    if (this.data) {
      this.data['desktopSize'] = this.getScreenSize(data);
    }
  }

  private getScreenSize(submittedFormData: any): { width: number, height: number } | null {
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
