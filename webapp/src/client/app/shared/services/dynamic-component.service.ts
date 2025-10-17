import { ComponentRef, ElementRef, EnvironmentInjector, inject, Injectable, ViewContainerRef } from '@angular/core';
import { SessionType, WebSession } from '@shared/models/web-session.model';

@Injectable({
  providedIn: 'root',
})
export class DynamicComponentService {
  private injector = inject(EnvironmentInjector);

  constructor() {}

  createComponent<T extends SessionType>(
    container: ViewContainerRef,
    sessionsContainerRef: ElementRef,
    webSession?: WebSession<T>,
  ) {
    if (!webSession || !webSession.component) {
      console.error('DynamicComponentService: Cannot create component - webSession or component is undefined', webSession);
      throw new Error('Cannot create component: webSession or component is undefined');
    }

    container.clear();
    const componentRef = container.createComponent(webSession.component, {
      environmentInjector: this.injector
    });

    if (webSession.data) {
      componentRef.instance.formData = webSession.data;
    }

    componentRef.instance.webSessionId = webSession.id;
    componentRef.instance.sessionsContainerElement = sessionsContainerRef;

    return componentRef;
  }

  destroyComponent<T>(componentRef: ComponentRef<T>): void {
    if (componentRef) {
      componentRef.destroy();
    }
  }
}
