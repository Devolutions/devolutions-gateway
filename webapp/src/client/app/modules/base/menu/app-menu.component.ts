import {Component, OnInit} from '@angular/core';
import {MainAppComponent} from '../main-app/main-app.component';
import {RouterMenuItem} from './model/router-menu-item.model';
import {BaseComponent} from "@shared/bases/base.component";
import {NavigationService} from "@shared/services/navigation.service";
import {noop} from "rxjs";
import {takeUntil} from "rxjs/operators";
import {WebSessionService} from "@shared/services/web-session.service";
import {KeyValue} from "@angular/common";
import {AuthService} from "@shared/services/auth.service";
import { ApiService } from '@gateway/shared/services/api.service';


@Component({
  selector: 'app-menu',
  templateUrl: './app-menu.component.html',
  styleUrls: ['app-menu.component.scss']
})
export class AppMenuComponent extends BaseComponent implements  OnInit {

  isAutoLoginOn: boolean = false;
  isMenuSlim: boolean = false;
  mainMenus: Map<string, RouterMenuItem> = new Map<string, RouterMenuItem>();
  version: string;
  gatewayLatestUpdateLink: string;
  hasNewVersion: boolean = false;

  constructor(public app: MainAppComponent,
              private navigationService: NavigationService,
              private webSessionService: WebSessionService,
              private authService: AuthService,
              private apiService: ApiService,
              ) {
    super();
    this.initMenu();
  }

  ngOnInit(): void {
    this.subscribeRouteChange();
    this.subscribeToIsAutoLoginOn();
    this.apiService.getVersion().subscribe((result) => {
      this.version = result.version;
    });
    this.apiService.getLatestVersion().subscribe((result) => {
      this.gatewayLatestUpdateLink = result.downloadLink || '';
      this.hasNewVersion = !isSameVersion(this.version, result.latestVersion);
    });
  }

  onClickGoToNewSessionTab(): void {
    if (this.navigationService.isCurrentRouteUrl(this.WEB_APP_CLIENT_URL)) {
      this.webSessionService.setupNewWebSession();
    } else {
      this.navigationService.navigateToNewSession().then(noop);
    }
  }

  private subscribeRouteChange(): void {
    this.navigationService.getRouteChange().pipe(takeUntil(this.destroyed$)).subscribe((navigationEnd) => {
      this.resetSelectedMenu(navigationEnd.url);
    });
  }

  private subscribeToIsAutoLoginOn(): void {
    this.authService.isAutoLoginOn.pipe(takeUntil(this.destroyed$))
      .subscribe(isAutoLoginOn => this.isAutoLoginOn = isAutoLoginOn);
  }

  private initMenu(): void {
    this.mainMenus = new Map<string, RouterMenuItem>();

    const sessionsMenuItem: RouterMenuItem = this.createMenuItem('Sessions',
                                    '',
                                    (): void => { this.navigationService.navigateToRoot().then(noop); },
                                    (url: string) => false,
                                    true);

    this.mainMenus.set('Sessions', sessionsMenuItem);
  }

  private createMenuItem( label: string,
                          icon: string,
                          action: () => void,
                          isSelectedFn: (url: string) => boolean = () => false,
                          blockClickSelected: boolean = false
                      ): RouterMenuItem {
    return new RouterMenuItem({ label, icon, action, isSelectedFn, blockClickSelected });
  }

  private resetSelectedMenu(url: string): void {
    const lowerUrl: string = url.toLowerCase();
    const menus: RouterMenuItem[] = [...this.mainMenus.values()];

    for (const menu of menus) {
      menu.setSelected(lowerUrl);
    }
  }

  /**
   * A comparison function for the keyvalue pipe to preserve original order.
   * This function always returns zero, indicating "no change" in order.
   * KAH Dec 16 2023
   */
  asIsOrder(a: KeyValue<string, RouterMenuItem>, b: KeyValue<string, RouterMenuItem>): number {
    return 1;
  }

  onMenuModeTogglerClick(): void {
    this.isMenuSlim = !this.isMenuSlim;
  }

  logout(): void {
    this.authService.logout();
  }

}

function isSameVersion(a: string, b: string): boolean {
  const aParts = a.split('.').map(Number);
  const bParts = b.split('.').map(Number);
  for (let i = 0; i < Math.min(aParts.length,bParts.length); i++) {
    if (aParts[i] !== bParts[i]) {
      return false;
    }
  }

  return true;
}