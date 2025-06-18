import {
  AfterViewInit,
  ChangeDetectorRef,
  Component,
  ElementRef,
  HostListener,
  OnDestroy,
  OnInit,
  Type,
  ViewChild,
} from '@angular/core';
import { BaseComponent } from '@shared/bases/base.component';
import { SessionDataTypeMap, SessionType, WebSession, WebSessionComponentType } from '@shared/models/web-session.model';
import { WebSessionService } from '@shared/services/web-session.service';
import { TabView } from 'primeng/tabview';
import { takeUntil } from 'rxjs/operators';
import { MainPanelComponent } from '../main-panel/main-panel.component';

@Component({
  selector: 'web-client-tab-view',
  templateUrl: './tab-view.component.html',
  styleUrls: ['./tab-view.component.scss'],
})
export class TabViewComponent extends BaseComponent implements OnInit, OnDestroy, AfterViewInit {
  @ViewChild('tabView') tabView: TabView;
  @ViewChild('sessionsContainer') sessionsContainer: ElementRef;

  webSessionTabs: WebSession<SessionType>[] = [];
  currentTabIndex = 0;

  constructor(
    private webSessionService: WebSessionService,
    private readonly cdr: ChangeDetectorRef,
  ) {
    super();
  }

  @HostListener('window:beforeunload', ['$event'])
  unloadNotification($event): void {
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
    const height: number = this.sessionsContainer.nativeElement.offsetHeight - WebSession.TOOLBAR_SIZE;
    this.webSessionService.setWebSessionScreenSize({ width, height });
  }

  private changeTabIndex(): void {
    if (!this.tabView) return;
    this.tabView.activeIndex = this.currentTabIndex;
  }

  private loadFormTab(): void {
    if (!this.isSessionTabExists('New Session')) {
      const newSessionTab = this.createNewSessionTab('New Session') as WebSession<keyof SessionDataTypeMap>;
      this.webSessionService.addSession(newSessionTab);
    }
  }

  private isSessionTabExists(tabName: string): boolean {
    return this.webSessionService.getWebSessionSnapshot().some((webSession) => webSession.name === tabName);
  }

  private createNewSessionTab(name: string) {
    return new WebSession(name, MainPanelComponent);
  }

  private subscribeToTabMenuArray(): void {
    this.webSessionService
      .getAllWebSessions()
      .pipe(takeUntil(this.destroyed$))
      .subscribe((tabs) => {
        this.webSessionTabs = tabs;
        this.cdr.detectChanges();
      });
  }

  private subscribeToTabActiveIndex(): void {
    this.webSessionService
      .getWebSessionCurrentIndex()
      .pipe(takeUntil(this.destroyed$))
      .subscribe((tabActiveIndex: number): void => {
        this.currentTabIndex = tabActiveIndex;
        this.changeTabIndex();
      });
  }
}
