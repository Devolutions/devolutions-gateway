import { Injectable, NgZone } from '@angular/core';
import { BehaviorSubject } from 'rxjs';

@Injectable({ providedIn: 'root' })
export class ComponentResizeObserverService {
  private resizeSubject = new BehaviorSubject<{ width: number; height: number } | null>(null);
  resize$ = this.resizeSubject.asObservable();

  private observer?: ResizeObserver;

  constructor(private ngZone: NgZone) {}

  observe(element: HTMLElement): () => void {
    this.observer?.disconnect();

    this.ngZone.runOutsideAngular(() => {
      this.observer = new ResizeObserver((entries) => {
        for (const _entry of entries) {
          const width: number = element.offsetWidth;
          const height: number = element.offsetHeight;

          this.resizeSubject.next({ width, height });
        }
      });

      this.observer.observe(element);
    });

    return () => {
      this.observer?.disconnect();
      this.observer = undefined;
    };
  }
}
