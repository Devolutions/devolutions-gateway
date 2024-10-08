import {
  AfterViewInit,
  ChangeDetectorRef,
  Component,
  ComponentRef,
  EventEmitter,
  Input,
  OnDestroy,
  Output,
  ViewChild,
  ViewContainerRef,
} from '@angular/core';

import { BaseComponent } from '@shared/bases/base.component';
import { ComponentStatus } from '@shared/models/component-status.model';
import { SessionType, WebSession, WebSessionComponentType } from '@shared/models/web-session.model';
import { DynamicComponentService } from '@shared/services/dynamic-component.service';
import { WebSessionService } from '@shared/services/web-session.service';

@Component({
  selector: 'web-client-dynamic-tab',
  templateUrl: './dynamic-tab.component.html',
  styleUrls: ['./dynamic-tab.component.scss'],
})
export class DynamicTabComponent<T extends SessionType> extends BaseComponent implements AfterViewInit, OnDestroy {
  @Input() webSessionTab: WebSession<T>;
  @ViewChild('dynamicComponentContainer', { read: ViewContainerRef }) container: ViewContainerRef;
  @Output() isDynamicTabInitialized: EventEmitter<boolean> = new EventEmitter<boolean>();
  @Output() componentRefSizeChange: EventEmitter<void> = new EventEmitter<void>();

  constructor(
    private cdr: ChangeDetectorRef,
    private webSessionService: WebSessionService,
    private dynamicComponentService: DynamicComponentService,
  ) {
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

    const componentRef = this.dynamicComponentService.createComponent(this.container, this.webSessionTab);

    this.cdr.detectChanges();

    componentRef.instance.componentStatus.subscribe((status: ComponentStatus) => this.onComponentDisabled(status));

    componentRef.instance?.sizeChange?.subscribe(() => this.componentRefSizeChange.emit());

    this.webSessionTab.componentRef = componentRef;
  }

  private onComponentDisabled(status: ComponentStatus): void {
    if (status.isDisabledByUser) {
      void this.webSessionService.removeSession(status.id);
    }
  }
}
