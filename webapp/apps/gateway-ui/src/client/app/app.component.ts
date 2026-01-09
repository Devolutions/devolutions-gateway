import { Component, OnDestroy, OnInit } from '@angular/core';
import { BaseComponent } from '@shared/bases/base.component';
import { AuthService } from '@shared/services/auth.service';
import { NavigationService } from '@shared/services/navigation.service';
import { BehaviorSubject } from 'rxjs';
import { takeUntil } from 'rxjs/operators';

@Component({
  standalone: false,
  selector: 'app-root',
  templateUrl: './app.component.html',
  styleUrls: ['./app.component.scss'],
})
export class AppComponent extends BaseComponent implements OnInit, OnDestroy {
  title = 'gateway-ui';
  isWebClientSession: BehaviorSubject<boolean> = new BehaviorSubject(true);

  constructor(
    private authService: AuthService,
    private readonly navigationService: NavigationService,
  ) {
    super();
  }

  ngOnInit(): void {
    this.subscribeRouteChanged();
    this.authService.startExpirationCheck();
  }

  ngOnDestroy(): void {
    this.authService.stopExpirationCheck();
  }

  private subscribeRouteChanged(): void {
    this.navigationService
      .getRouteChange()
      .pipe(takeUntil(this.destroyed$))
      .subscribe((navigationEnd) => {
        this.isWebClientSession.next(navigationEnd.url.startsWith(this.WEB_APP_CLIENT_URL));
      });
  }
}
