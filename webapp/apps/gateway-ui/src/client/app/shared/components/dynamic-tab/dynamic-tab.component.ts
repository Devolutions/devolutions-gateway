import {
  AfterViewInit,
  ChangeDetectorRef,
  Component,
  ComponentRef,
  ElementRef,
  EventEmitter,
  Input,
  OnChanges,
  OnDestroy,
  Output,
  SimpleChanges,
  ViewChild,
  ViewContainerRef,
} from '@angular/core';

import { WebClientFormComponent } from '@gateway/modules/web-client/form/web-client-form.component';
import { WebClientSshComponent } from '@gateway/modules/web-client/ssh/web-client-ssh.component';
import { WebClientTelnetComponent } from '@gateway/modules/web-client/telnet/web-client-telnet.component';
import { BaseComponent } from '@shared/bases/base.component';
import { WebComponentReady } from '@shared/bases/base-web-client.component';
import { ComponentStatus } from '@shared/models/component-status.model';
import { SessionType, WebSession } from '@shared/models/web-session.model';
import { ComponentListenerService } from '@shared/services/component-listener.service';
import { DynamicComponentService } from '@shared/services/dynamic-component.service';
import { WebSessionService } from '@shared/services/web-session.service';
import { distinctUntilChanged, take, takeUntil } from 'rxjs/operators';

@Component({
  standalone: false,
  selector: 'web-client-dynamic-tab',
  templateUrl: './dynamic-tab.component.html',
  styleUrls: ['./dynamic-tab.component.scss'],
})
export class DynamicTabComponent<T extends SessionType>
  extends BaseComponent
  implements OnChanges, AfterViewInit, OnDestroy
{
  @Input() webSessionTab: WebSession<T>;
  @Input() sessionsContainerElement: ElementRef;

  @ViewChild('dynamicComponentContainer', { read: ViewContainerRef }) container: ViewContainerRef;
  @Output() componentRefSizeChange: EventEmitter<void> = new EventEmitter<void>();

  /** Non-null while the reconnect form occupies the container slot. */
  private formRef: ComponentRef<WebClientFormComponent> | null = null;

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

  ngOnChanges(changes: SimpleChanges): void {
    if (!changes.webSessionTab || !this.container) {
      return;
    }

    // If the reconnect form was showing, the user submitted it and a new
    // session arrived via updateSession().  Clear the tracking ref so
    // initializeDynamicComponent() proceeds to create the protocol component
    // (which replaces the form inside createComponent's create-before-remove).
    if (this.formRef) {
      this.formRef = null;
    }

    this.initializeDynamicComponent();
  }

  initializeDynamicComponent(): void {
    if (!this.webSessionTab?.component) {
      return;
    }

    if (this.webSessionTab?.componentRef) {
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

  /**
   * Swap the protocol component out and put the reconnect form in its place.
   * Creates the form FIRST so the container slot is never empty, then removes
   * the old protocol component (mirrors the create-before-remove pattern used
   * in DynamicComponentService).
   */
  private swapToForm(status: ComponentStatus): void {
    const formRef = this.container.createComponent(WebClientFormComponent);
    formRef.instance.isFormExists = true;
    formRef.instance.webSessionId = this.webSessionTab.id;
    formRef.instance.inputFormData = this.webSessionTab.data;
    formRef.instance.sessionTerminationMessage = status.terminationMessage;

    // Remove the protocol component after the form is live.
    const previousCount = this.container.length - 1;
    for (let i = 0; i < previousCount; i++) {
      this.container.remove(0);
    }

    this.formRef = formRef;
    // Clear componentRef so initializeDynamicComponent() will recreate the
    // protocol component once the form is submitted.
    this.webSessionTab.componentRef = null;
    this.cdr.detectChanges();
  }

  private onComponentDisabled(status: ComponentStatus): void {
    if (status.isDisabledByUser) {
      // User clicked Disconnect — close the tab entirely.
      void this.webSessionService.removeSession(status.id);
      return;
    }

    // Connection failed or dropped — swap to the reconnect form.
    this.swapToForm(status);
  }
}
