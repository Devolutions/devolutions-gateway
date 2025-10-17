import {
  AfterViewInit,
  ChangeDetectorRef,
  Component,
  ElementRef,
  EventEmitter,
  Input,
  OnDestroy,
  Output,
  ViewChild,
  ViewContainerRef,
} from '@angular/core';

import { WebClientSshComponent } from '@gateway/modules/web-client/ssh/web-client-ssh.component';
import { WebClientTelnetComponent } from '@gateway/modules/web-client/telnet/web-client-telnet.component';
import { WebComponentReady } from '@shared/bases/base-web-client.component';
import { BaseComponent } from '@shared/bases/base.component';
import { ComponentStatus } from '@shared/models/component-status.model';
import { SessionType, WebSession } from '@shared/models/web-session.model';
import { ComponentListenerService } from '@shared/services/component-listener.service';
import { DynamicComponentService } from '@shared/services/dynamic-component.service';
import { WebSessionService } from '@shared/services/web-session.service';
import { distinctUntilChanged, take, takeUntil } from 'rxjs/operators';

@Component({
  selector: 'web-client-dynamic-tab',
  templateUrl: './dynamic-tab.component.html',
  styleUrls: ['./dynamic-tab.component.scss'],
  standalone: true
})
export class DynamicTabComponent<T extends SessionType> extends BaseComponent implements AfterViewInit, OnDestroy {
  @Input() webSessionTab: WebSession<T>;
  @Input() sessionsContainerElement: ElementRef;

  @ViewChild('dynamicComponentContainer', { read: ViewContainerRef }) container: ViewContainerRef;
  @Output() componentRefSizeChange: EventEmitter<void> = new EventEmitter<void>();

  constructor(
    private cdr: ChangeDetectorRef,
    private webSessionService: WebSessionService,
    private dynamicComponentService: DynamicComponentService,
    private componentListenerService: ComponentListenerService,
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
    if (!this.webSessionTab) {
      console.warn('DynamicTabComponent: webSessionTab is undefined');
      return;
    }

    if (!this.webSessionTab.component) {
      console.error('DynamicTabComponent: webSessionTab.component is undefined for session:', this.webSessionTab.id);
      return;
    }

    if (this.webSessionTab.componentRef) {
      return;
    }

    const componentRef = this.dynamicComponentService.createComponent(
      this.container,
      this.sessionsContainerElement,
      this.webSessionTab,
    );

    if ('webComponentReady' in componentRef.instance) {
      if (componentRef.instance instanceof WebClientTelnetComponent) {
        this.componentListenerService
          .onTelnetInitialized()
          .pipe(takeUntil(this.destroyed$), take(1))
          .subscribe((event) => {
            (componentRef.instance as WebComponentReady).webComponentReady(event as CustomEvent, this.webSessionTab.id);
          });
      } else if (componentRef.instance instanceof WebClientSshComponent) {
        this.componentListenerService
          .onSshInitialized()
          .pipe(takeUntil(this.destroyed$), take(1))
          .subscribe((event) => {
            (componentRef.instance as WebComponentReady).webComponentReady(event as CustomEvent, this.webSessionTab.id);
          });
      }
    }

    this.cdr.detectChanges();

    componentRef.instance.componentStatus
      .pipe(takeUntil(this.destroyed$), distinctUntilChanged())
      .subscribe((status: ComponentStatus) => {
        this.webSessionTab.status = status;
        if (status.isDisabled) {
          this.onComponentDisabled(status);
        }
      });

    componentRef.instance?.sizeChange
      ?.pipe(takeUntil(this.destroyed$))
      .subscribe(() => this.componentRefSizeChange.emit());

    this.webSessionTab.componentRef = componentRef;
  }

  private onComponentDisabled(status: ComponentStatus): void {
    if (status.isDisabledByUser) {
      void this.webSessionService.removeSession(status.id);
    }
  }
}
