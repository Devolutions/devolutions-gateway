import {ActivatedRoute, NavigationEnd, Router} from '@angular/router';
import {Injectable} from '@angular/core';
import {filter, map} from "rxjs/operators";
import {Observable} from "rxjs";

@Injectable({ providedIn: 'root' })
export class NavigationService {

  constructor(
    private readonly router: Router,
    private readonly activatedRoute: ActivatedRoute
  ) {
  }

  navigateToPath(anyPath: string): Promise<boolean> {
    return this.router.navigateByUrl(anyPath);
  }

  navigateToRoot(): Promise<boolean> {
    return this.router.navigateByUrl('/');
  }

  navigateToNewSession(): Promise<boolean> {
    return this.router.navigateByUrl('session');
  }

  navigateToRDPSession(connectionTypeRoute: WebClientSection, queryParams?: string) {
    const webClientUrl = `session/${connectionTypeRoute}` + (queryParams ?? '');
    return this.router.navigateByUrl(webClientUrl);
  }

  getRouteChange(): Observable<NavigationEnd> {
    return this.router.events.pipe(
      filter(value => value instanceof NavigationEnd),
      map(value => value as NavigationEnd)
    );
  }

  isCurrentRouteUrl(routeString: string): boolean {
    return this.router.url.toLowerCase() === routeString.toLowerCase();
  }
}

export enum WebClientSection {
  powerShell = 'powershell',
  rdp = 'rdp',
  ssh = 'ssh',
  telnet = 'telnet'
}
