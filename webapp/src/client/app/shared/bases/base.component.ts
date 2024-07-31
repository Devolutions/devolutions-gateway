import { Directive, OnDestroy } from '@angular/core';
import { Subject } from 'rxjs';

@Directive()
export abstract class BaseComponent implements OnDestroy {
  WEB_APP_CLIENT_URL = '/session';

  protected destroyed$: Subject<boolean> = new Subject<boolean>();

  protected constructor() {}

  ngOnDestroy(): void {
    this.destroyed$.next(true);
    this.destroyed$.complete();
  }
}
