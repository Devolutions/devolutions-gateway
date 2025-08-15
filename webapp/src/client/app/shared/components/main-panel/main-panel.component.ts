import { AfterViewInit, Component, EventEmitter, Output, ViewChild } from '@angular/core';
import { WebClientFormComponent } from '@gateway/modules/web-client/form/web-client-form.component';
import { NetScanComponent } from '@gateway/modules/web-client/net-scan/net-scan.component';
import { ComponentStatus } from '@gateway/shared/models/component-status.model';
import { BaseSessionComponent } from '@gateway/shared/models/web-session.model';

@Component({
  selector: 'app-main-panel',
  templateUrl: './main-panel.component.html',
  styleUrls: ['./main-panel.component.scss'],
  standalone: true,
  imports: [WebClientFormComponent, NetScanComponent],
})
export class MainPanelComponent extends BaseSessionComponent implements AfterViewInit {
  @Output() componentStatus: EventEmitter<ComponentStatus> = new EventEmitter<ComponentStatus>();

  @Output() sizeChange: EventEmitter<void> = new EventEmitter<void>();

  @ViewChild(WebClientFormComponent)
  webClientFormComponent!: WebClientFormComponent;

  formData: unknown;

  constructor() {
    super();
  }

  ngAfterViewInit(): void {
    if (!this.webClientFormComponent) {
      return;
    }
    this.webClientFormComponent.componentStatus.subscribe((status: ComponentStatus) => {
      this.componentStatus.emit(status);
    });

    this.webClientFormComponent.sizeChange.subscribe(() => {
      this.sizeChange.emit();
    });
  }
}
