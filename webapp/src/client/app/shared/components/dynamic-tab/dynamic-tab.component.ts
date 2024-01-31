import {
  Component,
  Input,
  ViewChild,
  ViewContainerRef,
  ComponentRef,
  AfterViewInit,
  ChangeDetectorRef,
  Output, EventEmitter, OnDestroy
} from '@angular/core';

import {WebSession} from "@shared/models/web-session.model";
import {WebSessionService} from "@shared/services/web-session.service";
import {BaseComponent} from "@shared/bases/base.component";
import {DynamicComponentService} from "@shared/services/dynamic-component.service";
import {ComponentStatus} from "@shared/models/component-status.model";

@Component({
  selector: 'web-client-dynamic-tab',
  templateUrl: './dynamic-tab.component.html',
  styleUrls: ['./dynamic-tab.component.scss']
})
export class DynamicTabComponent extends BaseComponent implements AfterViewInit, OnDestroy {

  @Input() webSessionTab: WebSession<any, any>;
  @ViewChild('dynamicComponentContainer', { read: ViewContainerRef }) container: ViewContainerRef;
  @Output() isDynamicTabInitialized: EventEmitter<boolean> = new EventEmitter<boolean>();

  constructor(private cdr: ChangeDetectorRef,
              private webSessionService: WebSessionService,
              private dynamicComponentService: DynamicComponentService) {
    super();
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
    const tabIndex: number = this.webSessionTab.tabIndex;
    const componentRef: ComponentRef<any> = this.dynamicComponentService.createComponent(this.webSessionTab.component, this.container, inputData, tabIndex);

    if (this.webSessionTab?.data?.hostname) {
      componentRef["hostname"] = this.webSessionTab.data.hostname;
    }

    this.cdr.detectChanges();

    //TODO not sure if BOTH event emitters are needed anymore.
    componentRef.instance.componentStatus.subscribe((status: ComponentStatus) => this.onComponentDisabled(status, componentRef));

    this.webSessionTab.componentRef = componentRef;
  }

  private onComponentDisabled(status: ComponentStatus, componentRef: ComponentRef<any>): void {
    if (status.isDisabledByUser) {
      this.webSessionService.removeSession(status.tabIndex);
    }
  }
}
