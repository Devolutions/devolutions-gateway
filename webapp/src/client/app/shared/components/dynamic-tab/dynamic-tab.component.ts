import {
  Component,
  Input,
  ViewChild,
  ViewContainerRef,
  ComponentRef,
  AfterContentInit,
  AfterViewInit,
  ChangeDetectorRef,
  Output, EventEmitter, OnDestroy
} from '@angular/core';
import {takeUntil} from "rxjs/operators";

import {WebSession} from "@shared/models/web-session.model";
import {SESSIONS_MENU_OFFSET, WebSessionService} from "@shared/services/web-session.service";
import {BaseComponent} from "@shared/bases/base.component";
import {DynamicComponentService} from "@shared/services/dynamic-component.service";
import {noop} from "rxjs";

@Component({
  selector: 'web-client-dynamic-tab',
  templateUrl: './dynamic-tab.component.html',
  styleUrls: ['./dynamic-tab.component.scss']
})
export class DynamicTabComponent extends BaseComponent implements AfterContentInit, AfterViewInit, OnDestroy {

  @Input() webSessionTab: WebSession<any, any>;
  @ViewChild('dynamicComponentContainer', { read: ViewContainerRef }) container: ViewContainerRef;
  @Output() isDynamicTabInitialized: EventEmitter<boolean> = new EventEmitter<boolean>();

  componentTabIndex: number = 0;
  activeTabIndex: number = 0;

  constructor(private cdr: ChangeDetectorRef,
              private webSessionService: WebSessionService,
              private dynamicComponentService: DynamicComponentService) {
    super();
  }

  ngAfterContentInit(): void {
    this.subscribeToActiveTabIndexChanges();
  }

  ngAfterViewInit(): void {
    this.initializeDynamicComponent();
  }

  ngOnDestroy(): void {
    //TODO Clean up componentRefs ??
    super.ngOnDestroy();
  }

  initializeDynamicComponent(): void {
    if (!this.webSessionTab?.component) {
      return;
    }

    const inputData: {formData: any} = { formData: this.webSessionTab.data };
    const componentRef: ComponentRef<any> = this.dynamicComponentService.createComponent(this.webSessionTab.component, this.container, inputData);

    if (this.webSessionTab?.data?.hostname) {
      componentRef["hostname"] = this.webSessionTab.data.hostname;
    }
    this.webSessionTab.componentRef = componentRef;
    this.cdr.detectChanges();

    componentRef.instance.isComponentViewInitialized.pipe(takeUntil(this.destroyed$)).subscribe((isInitialized: boolean): void => {
      if (!isInitialized) {
        this.onComponentNotInitialized(this.activeTabIndex, componentRef);
      }
    });
  }

  private subscribeToActiveTabIndexChanges(): void {
    this.webSessionService.getWebSessionCurrentIndex().pipe(takeUntil(this.destroyed$)).subscribe((webSessionActiveIndex: number): void => {
      this.activeTabIndex = webSessionActiveIndex;
      this.componentTabIndex = webSessionActiveIndex-SESSIONS_MENU_OFFSET;
    })
  }

  private onComponentNotInitialized(index: number, componentRef: ComponentRef<any>): void {
    this.webSessionService.removeSession(index).then(noop);
  }
}
