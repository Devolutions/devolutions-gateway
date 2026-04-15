import { ComponentRef, ElementRef, Injectable, ViewContainerRef } from '@angular/core';
import { SessionType, WebSession } from '@shared/models/web-session.model';

@Injectable({
  providedIn: 'root',
})
export class DynamicComponentService {
  constructor() {}

  createComponent<T extends SessionType>(
    container: ViewContainerRef,
    sessionsContainerRef: ElementRef,
    webSession?: WebSession<T>,
  ) {
    // Create the new component FIRST so that Angular's style reference count
    // goes 1→2 rather than 1→0→1. Removing the old view(s) after creation
    // keeps the count at 1 the whole time — the <style> element is never
    // removed from the document, which prevents the `:host` styles from
    // disappearing on the reconnect path.
    const componentRef = container.createComponent(webSession.component);

    if (webSession.data) {
      componentRef.instance.formData = webSession.data;
    }

    componentRef.instance.webSessionId = webSession.id;
    componentRef.instance.sessionsContainerElement = sessionsContainerRef;

    // Remove any pre-existing views (old protocol component) that were in the
    // container before we created the new one. They sit at indices 0..length-2;
    // the new component is always at the last index.
    const previousCount = container.length - 1;
    for (let i = 0; i < previousCount; i++) {
      container.remove(0);
    }

    return componentRef;
  }

  destroyComponent<T>(componentRef: ComponentRef<T>): void {
    if (componentRef) {
      componentRef.destroy();
    }
  }
}
