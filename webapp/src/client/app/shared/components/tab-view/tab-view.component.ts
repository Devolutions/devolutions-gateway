import {
  Component,
  OnInit,
  ViewChild,
  ChangeDetectorRef, Type, OnDestroy, HostListener, ElementRef, AfterViewInit
} from '@angular/core';
import {takeUntil} from "rxjs/operators";
import {TabView} from "primeng/tabview";

import {WebSession} from "@shared/models/web-session.model";
import {WebSessionService} from "@shared/services/web-session.service";

import {BaseComponent} from "@shared/bases/base.component";
import {WebClientFormComponent} from "@gateway/modules/web-client/form/web-client-form.component";
import { MainPanelComponent } from '../main-panel/main-panel.component';

@Component({
  selector: 'web-client-tab-view',
  templateUrl: './tab-view.component.html',
  styleUrls: ['./tab-view.component.scss']
})
export class TabViewComponent extends BaseComponent implements OnInit, OnDestroy, AfterViewInit {

  @ViewChild('tabView') tabView: TabView;
  @ViewChild('sessionsContainer') sessionsContainer: ElementRef;

  webSessionTabs: WebSession<any, any>[] = [];
  currentTabIndex: number = 0;

  constructor(private webSessionService: WebSessionService,
              private readonly cdr: ChangeDetectorRef) {
    super();
  }

  @HostListener('window:beforeunload', ['$event'])
  unloadNotification($event: any): void {
    if (this.webSessionService.hasActiveWebSessions()) {
      $event.preventDefault();
      $event.returnValue = true;
      // KAH Jan 2024
      // Note: Custom message is not shown in most modern browsers due to security reasons
    }
  }

  ngOnInit(): void {
    this.loadFormTab();
    this.subscribeToTabMenuArray();
    this.subscribeToTabActiveIndex();
  }

  ngAfterViewInit(): void {
    this.measureSize();
  }

  ngOnDestroy(): void {
    super.ngOnDestroy();
  }

  addBackgroundClass(): boolean {
    return this.currentTabIndex > 0;
  }

  measureSize(): void {
    const width: number = this.sessionsContainer.nativeElement.offsetWidth;
    const height: number = this.sessionsContainer.nativeElement.offsetHeight-WebSession.TOOLBAR_SIZE;
    this.webSessionService.setWebSessionScreenSize({ width, height });
  }

  private changeTabIndex(): void {
    if (!this.tabView) return;
    this.tabView.activeIndex = this.currentTabIndex;
  }

  private loadFormTab(): void {
    const newSessionTabExists: boolean = this.webSessionService.getWebSessionSnapshot().some(webSession => webSession.name === 'New Session');

    if (!newSessionTabExists) {
      const newSessionTab: WebSession<Type<MainPanelComponent>, any> = new WebSession('New Session', MainPanelComponent);
      this.webSessionService.addSession(newSessionTab);
    }
  }

  private subscribeToTabMenuArray(): void {
    this.webSessionService.getAllWebSessions().pipe(takeUntil(this.destroyed$)).subscribe(
      (tabs: WebSession<any, any>[]) => {
        this.webSessionTabs = tabs;
        this.cdr.detectChanges();
    });
  }

  private subscribeToTabActiveIndex(): void {
    this.webSessionService.getWebSessionCurrentIndex().pipe(takeUntil(this.destroyed$)).subscribe(
      (tabActiveIndex: number): void => {
        this.currentTabIndex = tabActiveIndex;
        this.changeTabIndex();
    })
  }
}
