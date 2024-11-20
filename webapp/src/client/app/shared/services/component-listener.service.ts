import { Injectable, OnDestroy, Renderer2, RendererFactory2 } from '@angular/core';
import { Observable, Subject } from 'rxjs';

@Injectable({ providedIn: 'root' })
export class ComponentListenerService implements OnDestroy {
  private readonly renderer: Renderer2;
  private readonly listeners: Array<() => void> = [];

  private readonly sshInitialized$ = new Subject<Event>();
  private readonly telnetInitialized$ = new Subject<Event>();

  constructor(rendererFactory: RendererFactory2) {
    this.renderer = rendererFactory.createRenderer(null, null);

    const sshListener = this.renderer.listen('window', 'sshInitialized', (event) => {
      this.handleSshInitializedEvent(event as CustomEvent);
    });
    this.listeners.push(sshListener);

    const telnetListener = this.renderer.listen('window', 'telnetInitialized', (event) => {
      this.handleTelnetInitializedEvent(event as CustomEvent);
    });
    this.listeners.push(telnetListener);
  }

  ngOnDestroy(): void {
    this.destroyAllListeners();
  }

  onSshInitialized(): Observable<Event> {
    return this.sshInitialized$.asObservable();
  }

  onTelnetInitialized(): Observable<Event> {
    return this.telnetInitialized$.asObservable();
  }

  private destroyAllListeners(): void {
    for (const unsubscribe of this.listeners) {
      unsubscribe();
    }
    this.listeners.length = 0;

    this.sshInitialized$.complete();
    this.telnetInitialized$.complete();
  }

  private handleSshInitializedEvent(event: CustomEvent): void {
    this.sshInitialized$.next(event);
  }

  private handleTelnetInitializedEvent(event: CustomEvent): void {
    this.telnetInitialized$.next(event);
  }
}
