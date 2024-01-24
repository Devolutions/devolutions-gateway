import { Injectable, ViewContainerRef, ComponentRef, Type } from '@angular/core';
import {Subject} from "rxjs";

@Injectable({
    providedIn: 'root'
})
export class DynamicComponentService {
  constructor() {}

  createComponent<T>(component: Type<T>, container: ViewContainerRef, data?: any, tabIndex?: number): ComponentRef<T> {
    container.clear();
    const componentRef: ComponentRef<any> = container.createComponent(component);

    if (data) {
      for (const key of Object.keys(data)) {
        componentRef.instance[key] = data[key];
      }
    }
    componentRef.instance["tabIndex"] = tabIndex;
    return componentRef;
  }

  destroyComponent(componentRef: ComponentRef<any>): void {
    console.log('destroyComponent', componentRef.componentType.name);
    if (componentRef) {
     componentRef.destroy();
    }
  }
}
