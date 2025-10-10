import { Injectable } from '@angular/core';
import { ActivatedRouteSnapshot, Resolve, RouterStateSnapshot } from '@angular/router';
import { init as rdp_init } from '@devolutions/iron-remote-desktop-rdp';
import { init as vnc_init } from '@devolutions/iron-remote-desktop-vnc';
import { forkJoin, from, Observable } from 'rxjs';
import { map } from 'rxjs/operators';

// This resolver initializes the VNC and RDP WASM modules.
@Injectable({
  providedIn: 'root',
})
export class WasmInitResolver implements Resolve<void> {
  constructor() {}

  resolve(_route: ActivatedRouteSnapshot, _state: RouterStateSnapshot): Observable<void> {
    return forkJoin([from(rdp_init('INFO')), from(vnc_init('INFO'))]).pipe(map(() => void 0));
  }
}
