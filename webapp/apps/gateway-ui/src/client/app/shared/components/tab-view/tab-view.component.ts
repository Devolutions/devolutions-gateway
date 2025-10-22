import {
  AfterViewInit,
  ChangeDetectorRef,
  Component,
  ElementRef,
  HostListener,
  OnDestroy,
  Type,
  ViewChild,
} from '@angular/core';
import { ActivatedRoute } from '@angular/router';
import { WebClientRdpComponent } from '@gateway/modules/web-client/rdp/web-client-rdp.component';
import { BaseComponent } from '@shared/bases/base.component';
import { ComponentForSession, SessionDataTypeMap, SessionType, WebSession } from '@shared/models/web-session.model';
import { WebSessionService } from '@shared/services/web-session.service';
import { Tabs } from 'primeng/tabs';
import { takeUntil } from 'rxjs/operators';
import { MainPanelComponent } from '../main-panel/main-panel.component';

@Component({
  standalone: false,
  selector: 'web-client-tab-view',
  templateUrl: './tab-view.component.html',
  styleUrls: ['./tab-view.component.scss'],
})
export class TabViewComponent extends BaseComponent implements OnDestroy, AfterViewInit {
  @ViewChild('tabView') tabView: Tabs;
  @ViewChild('sessionsContainer') sessionsContainerRef: ElementRef;

  webSessionTabs: WebSession<SessionType>[] = [];
  currentTabIndex = 0;

  constructor(
    private webSessionService: WebSessionService,
    private readonly cdr: ChangeDetectorRef,
    private activatedRoute: ActivatedRoute,
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

  ngAfterViewInit(): void {
    // Load tabs after the component's view is initialized because we need the `@ViewChild` references to be populated.
    this.loadTabs();
    this.subscribeToTabMenuArray();
    this.subscribeToTabActiveIndex();

    this.measureSize();
  }

  ngOnDestroy(): void {
    super.ngOnDestroy();
  }

  addBackgroundClass(): boolean {
    return this.currentTabIndex > 0;
  }

  measureSize(): void {
    const width: number = this.sessionsContainerRef.nativeElement.offsetWidth;
    const height: number = this.sessionsContainerRef.nativeElement.offsetHeight - WebSession.TOOLBAR_SIZE;
    this.webSessionService.setWebSessionScreenSize({ width, height });
  }

  onTabChange(event: any): void {
    // PrimeNG 20 Tabs onChange event provides the new value in event.value
    const newIndex = typeof event.value === 'number' ? event.value : Number.parseInt(event.value, 10);
    this.webSessionService.setWebSessionCurrentIndex(newIndex);
  }

  private changeTabIndex(): void {
    if (!this.tabView) return;
    // PrimeNG 20 Tabs uses 'value' signal instead of 'activeIndex'
    // The value should be a number matching the tab's [value] attribute
    this.tabView.value.set(this.currentTabIndex);
  }

  private loadTabs(): void {
    const queryParams = this.activatedRoute.snapshot.queryParams;

    // Autoconnect only if the `config` parameter exists and `autoconnect` is `true`.
    const autoconnect: boolean = !!queryParams.config && queryParams.autoconnect === 'true';

    // TODO: Fill the form with the configuration from config parameter.
    this.loadFormTab();

    if (autoconnect) {
      const protocol: string = queryParams.protocol?.toLowerCase() ?? 'rdp';

      if (protocol === 'rdp') {
        // Unfortunately, the hostname cannot be retrieved at this point, so we will use a placeholder
        // for the session tab name.
        // TODO(Improvement): Rename the session tab after the config will be parsed.
        this.loadWebSessionTab('RDP Session', WebClientRdpComponent);
      }
      // TODO: Support more protocols.
    }
  }

  private loadFormTab(): void {
    if (!this.isSessionTabExists('New Session')) {
      const newSessionTab = this.createNewSessionTab('New Session') as WebSession<keyof SessionDataTypeMap>;
      this.webSessionService.addSession(newSessionTab);
    }
  }

  private loadWebSessionTab(name: string, component: Type<ComponentForSession<keyof SessionDataTypeMap>>): void {
    const newSessionTab = new WebSession(name, component);
    this.webSessionService.addSession(newSessionTab);
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
