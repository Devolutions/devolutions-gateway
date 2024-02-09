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
import {BaseComponent} from "@shared/bases/base.component";
import {DynamicComponentService} from "@shared/services/dynamic-component.service";

@Component({
  selector: 'web-client-dynamic-tab',
  templateUrl: './dynamic-tab.component.html',
  styleUrls: ['./dynamic-tab.component.scss']
})
export class DynamicTabComponent extends BaseComponent implements AfterViewInit, OnDestroy {

  @Input() webSessionTab: WebSession<any, any>;
  @ViewChild('dynamicComponentContainer', { read: ViewContainerRef }) container: ViewContainerRef;
  @Output() isDynamicTabInitialized: EventEmitter<boolean> = new EventEmitter<boolean>();
  @Output() componentRefSizeChange: EventEmitter<void> = new EventEmitter<void>();

  constructor(private cdr: ChangeDetectorRef,
              private dynamicComponentService: DynamicComponentService) {
    super();
  }

  ngAfterViewInit(): void {
    this.initializeDynamicComponent();
  }

  ngOnDestroy(): void {
    super.ngOnDestroy();
  }

  initializeDynamicComponent(): void {
    if (!this.webSessionTab?.component) {
      return;
    }

    if (this.webSessionTab?.componentRef) {
      return;
    }

    const inputData: {formData: any} = { formData: this.webSessionTab.data };

    const componentRef: ComponentRef<any> = this.dynamicComponentService.
      createComponent(
        this.webSessionTab.component,
        this.container,
        inputData,
        this.webSessionTab);

    this.cdr.detectChanges();

    componentRef.instance?.sizeChange?.
      subscribe(() => this.componentRefSizeChange.emit());

    this.webSessionTab.componentRef = componentRef;
  }
}
