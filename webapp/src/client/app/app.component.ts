import { Component, OnInit } from '@angular/core';
import {BehaviorSubject} from "rxjs";
import {takeUntil} from "rxjs/operators";
import { BaseComponent } from "@shared/bases/base.component";
import { NavigationService } from "@shared/services/navigation.service";


@Component({
  selector: 'app-root',
  templateUrl: './app.component.html',
  styleUrls: ['./app.component.scss']
})
export class AppComponent extends BaseComponent implements OnInit {
  title: string = 'gateway-ui';
  isWebClientSession: BehaviorSubject<boolean> = new BehaviorSubject(true);

  constructor(private readonly navigationService: NavigationService) {
    super();
  }

  ngOnInit(): void {
    this.subscribeRouteChanged();
  }

  private subscribeRouteChanged() {
    this.navigationService.getRouteChange().pipe(takeUntil(this.destroyed$)).subscribe((navigationEnd) => {
      this.isWebClientSession.next(navigationEnd.url.startsWith(this.WEB_APP_CLIENT_URL) || navigationEnd.url.startsWith('/dashboard'));
    });
  }
}
