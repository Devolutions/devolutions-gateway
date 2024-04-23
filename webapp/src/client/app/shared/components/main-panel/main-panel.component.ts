import {
  AfterViewInit,
  Component,
  EventEmitter,
  Output,
  ViewChild,
} from '@angular/core';
import { ComponentStatus } from '@gateway/shared/models/component-status.model';
import { WebClientFormComponent } from '../../../modules/web-client/form/web-client-form.component';

@Component({
  selector: 'app-main-panel',
  templateUrl: './main-panel.component.html',
  styleUrls: ['./main-panel.component.scss'],
})
export class MainPanelComponent implements AfterViewInit {
  @Output() componentStatus: EventEmitter<ComponentStatus> =
    new EventEmitter<ComponentStatus>();

  @Output() sizeChange: EventEmitter<void> = new EventEmitter<void>();

  @ViewChild(WebClientFormComponent)
  webClientFormComponent!: WebClientFormComponent;

  constructor() {}

  ngAfterViewInit(): void {
    if (!this.webClientFormComponent) {
      return;
    }
    this.webClientFormComponent.componentStatus.subscribe(
      (status: ComponentStatus) => {
        this.componentStatus.emit(status);
      }
    );

    this.webClientFormComponent.sizeChange.subscribe(() => {
      this.sizeChange.emit();
    });
  }
}
