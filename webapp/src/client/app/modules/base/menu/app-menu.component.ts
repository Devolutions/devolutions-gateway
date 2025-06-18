import { KeyValue } from '@angular/common';
import { Component, OnInit } from '@angular/core';
import { ApiService } from '@gateway/shared/services/api.service';
import { BaseComponent } from '@shared/bases/base.component';
import { AuthService } from '@shared/services/auth.service';
import { NavigationService } from '@shared/services/navigation.service';
import { WebSessionService } from '@shared/services/web-session.service';
import { noop } from 'rxjs';
import { takeUntil } from 'rxjs/operators';
import { MainAppComponent } from '../main-app/main-app.component';
import { RouterMenuItem } from './model/router-menu-item.model';

@Component({
  selector: 'app-menu',
  templateUrl: './app-menu.component.html',
  styleUrls: ['app-menu.component.scss'],
})
export class AppMenuComponent extends BaseComponent implements OnInit {
  isAutoLoginOn = false;
  isMenuSlim = false;
  mainMenus: Map<string, RouterMenuItem> = new Map<string, RouterMenuItem>();
  version: string;
  latestVersion: string;
  gatewayLatestUpdateLink: string;

  constructor(
    public app: MainAppComponent,
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
      this.latestVersion = result.latestVersion;
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
    this.navigationService
      .getRouteChange()
      .pipe(takeUntil(this.destroyed$))
      .subscribe((navigationEnd) => {
        this.resetSelectedMenu(navigationEnd.url);
      });
  }

  private subscribeToIsAutoLoginOn(): void {
    this.authService.isAutoLoginOn.pipe(takeUntil(this.destroyed$)).subscribe((isAutoLoginOn) => {
      this.isAutoLoginOn = isAutoLoginOn;
    });
  }

  private initMenu(): void {
    this.mainMenus = new Map<string, RouterMenuItem>();

    const sessionsMenuItem: RouterMenuItem = this.createMenuItem(
      'Sessions',
      '',
      (): void => {
        this.navigationService.navigateToRoot().then(noop);
      },
      (_url: string) => false,
      true,
    );

    this.mainMenus.set('Sessions', sessionsMenuItem);
  }

  private createMenuItem(
    label: string,
    icon: string,
    action: () => void,
    isSelectedFn: (url: string) => boolean = () => false,
    blockClickSelected = false,
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
  asIsOrder(_a: KeyValue<string, RouterMenuItem>, _b: KeyValue<string, RouterMenuItem>): number {
    return 1;
  }

  onMenuModeTogglerClick(): void {
    this.isMenuSlim = !this.isMenuSlim;
  }

  logout(): void {
    this.authService.logout();
  }

  downloadVersionToolTip() {
    return `New version ${this.latestVersion} available`;
  }

  hasNewVersion() {
    return this.version && this.latestVersion && compareVersion(this.version, this.latestVersion) < 0;
  }
}

function compareVersion(a: string, b: string) {
  const partsA = a.split('.');
  const partsB = b.split('.');
  for (let i = 0; i < partsA.length; i++) {
    if (Number.parseInt(partsA[i]) > Number.parseInt(partsB[i])) {
      return 1;
    }
    if (Number.parseInt(partsA[i]) < Number.parseInt(partsB[i])) {
      return -1;
    }
  }
  return 0;
}
