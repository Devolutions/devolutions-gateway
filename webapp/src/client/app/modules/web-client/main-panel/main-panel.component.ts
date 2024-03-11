import { AfterViewInit, Component, EventEmitter, Output, ViewChild } from '@angular/core';
import { ComponentStatus } from '@shared/models/component-status.model';
import { WebClientFormComponent } from '../form/web-client-form.component';

@Component({
  selector: 'app-main-panel',
  templateUrl: './main-panel.component.html',
  styleUrls: ['./main-panel.component.scss']
})
export class MainPanelComponent implements AfterViewInit{
  @Output() componentStatus: EventEmitter<ComponentStatus> = new EventEmitter<ComponentStatus>();
  @ViewChild('form') form : WebClientFormComponent;

  ngAfterViewInit(): void {
    this.form.componentStatus.subscribe((status: ComponentStatus) => {
      this.componentStatus.emit(status);
    })
  }
}
