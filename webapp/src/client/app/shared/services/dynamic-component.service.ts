import { ComponentRef, Injectable, Type, ViewContainerRef } from '@angular/core';
import { DataForSession, SessionType, WebSession } from '@shared/models/web-session.model';

@Injectable({
  providedIn: 'root',
})
export class DynamicComponentService {
  constructor() {}

  createComponent<T extends SessionType>(container: ViewContainerRef, webSession?: WebSession<T>) {
    container.clear();
    const componentRef = container.createComponent(webSession.component);

    if (webSession.data) {
      componentRef.instance.formData = webSession.data;
    }

    componentRef.instance.webSessionId = webSession.id;

    return componentRef;
  }

  destroyComponent<T>(componentRef: ComponentRef<T>): void {
    if (componentRef) {
      componentRef.destroy();
    }
  }
}
