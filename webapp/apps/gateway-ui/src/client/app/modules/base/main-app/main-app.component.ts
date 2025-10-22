import { Component, OnInit } from '@angular/core';
import { AppComponent } from '@gateway/app.component';
import { BaseComponent } from '@shared/bases/base.component';
import { MainMenuService } from '@shared/services/main-menu.service';
import { takeUntil } from 'rxjs/operators';

@Component({
  standalone: false,
  templateUrl: './main-app.component.html',
  styleUrls: ['./main-app.component.scss'],
})
export class MainAppComponent extends BaseComponent implements OnInit {
  staticMenuMobileActive = false;
  isMenuCollapsed = true;
  isMenuVisible = true;
  isWebClientSession = false;

  constructor(
    private mainMenuService: MainMenuService,
    public app: AppComponent,
  ) {
    super();
  }

  ngOnInit(): void {
    this.subscribeToWebClientSession();
    this.subscribeToMainMenu();
  }

  private subscribeToMainMenu(): void {
    this.mainMenuService.isCollapsed.pipe(takeUntil(this.destroyed$)).subscribe((isCollapsed) => {
      this.isMenuCollapsed = isCollapsed;
    });

    this.mainMenuService.isVisible.pipe(takeUntil(this.destroyed$)).subscribe((isVisible) => {
      this.isMenuVisible = isVisible;
    });
  }

  private subscribeToWebClientSession(): void {
    this.app.isWebClientSession.pipe(takeUntil(this.destroyed$)).subscribe((isWebClientSession) => {
      this.isWebClientSession = isWebClientSession;
    });
  }
}
