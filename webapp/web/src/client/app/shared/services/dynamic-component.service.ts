import { Injectable, ViewContainerRef, ComponentRef, Type } from '@angular/core';

@Injectable({
    providedIn: 'root'
})
export class DynamicComponentService {
    constructor() {}


    createComponent<T>(component: Type<T>, container: ViewContainerRef, data?: any): ComponentRef<T> {
      container.clear();
      const componentRef: ComponentRef<any> = container.createComponent(component);

      if (data) {
        for (const key of Object.keys(data)) {
            componentRef.instance[key] = data[key];
        }
      }

      return componentRef;
    }

    destroyComponent(componentRef: ComponentRef<any>): void {
        console.log('destroyComponent', componentRef);
        if (componentRef) {
           componentRef.destroy();
        }
    }
}
