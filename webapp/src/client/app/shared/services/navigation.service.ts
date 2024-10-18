import { Injectable } from '@angular/core';
import { ActivatedRoute, NavigationEnd, Router } from '@angular/router';
import { Observable } from 'rxjs';
import { filter, map } from 'rxjs/operators';

@Injectable({ providedIn: 'root' })
export class NavigationService {
  private static readonly SESSION_KEY: string = 'session';
  private static readonly LOGIN_KEY: string = 'login';

  constructor(
    private readonly router: Router,
    private readonly activatedRoute: ActivatedRoute,
  ) {}

  navigateToPath(anyPath: string): Promise<boolean> {
    return this.router.navigateByUrl(anyPath);
  }

  navigateToLogin(): Promise<boolean> {
    return this.router.navigateByUrl(NavigationService.LOGIN_KEY);
  }

  navigateToRoot(): Promise<boolean> {
    return this.router.navigateByUrl('/');
  }

  navigateToNewSession(): Promise<boolean> {
    if (this.isCurrentRouteUrl(NavigationService.SESSION_KEY)) {
      return;
    }
    return this.router.navigateByUrl(NavigationService.SESSION_KEY);
  }

  navigateToRDPSession(connectionTypeRoute: WebClientSection, queryParams?: string) {
    const webClientUrl = `session/${connectionTypeRoute}` + (queryParams ?? '');
    return this.router.navigateByUrl(webClientUrl);
  }

  getRouteChange(): Observable<NavigationEnd> {
    return this.router.events.pipe(
      filter((value) => value instanceof NavigationEnd),
      map((value) => value as NavigationEnd),
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
  telnet = 'telnet',
}
