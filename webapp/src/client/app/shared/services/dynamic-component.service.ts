import { Injectable, ViewContainerRef, ComponentRef, Type } from '@angular/core';
import {WebSession} from "@shared/models/web-session.model";

@Injectable({
    providedIn: 'root'
})
export class DynamicComponentService {
  constructor() {}

  createComponent<T>(component: Type<T>, container: ViewContainerRef, data?: any, webSession?: WebSession<any, any>): ComponentRef<T> {
    container.clear();
    const componentRef: ComponentRef<any> = container.createComponent(component);

    if (data) {
      for (const key of Object.keys(data)) {
        componentRef.instance[key] = data[key];
      }
    }
    if (webSession?.data?.hostname) {
      componentRef["hostname"] = webSession.data.hostname;
    }
    componentRef.instance["webSessionId"] = webSession.id;

    return componentRef;
  }

  destroyComponent(componentRef: ComponentRef<any>): void {
    if (componentRef) {
     componentRef.destroy();
    }
  }
}
