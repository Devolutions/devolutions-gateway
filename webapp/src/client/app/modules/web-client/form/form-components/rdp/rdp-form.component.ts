import { Component, Input, OnInit } from '@angular/core';
import { FormGroup } from '@angular/forms';

import { BaseComponent } from '@shared/bases/base.component';

@Component({
  selector: 'rdp-form',
  templateUrl: 'rdp-form.component.html',
  styleUrls: ['rdp-form.component.scss'],
})
export class RdpFormComponent extends BaseComponent implements OnInit {
  @Input() form: FormGroup;
  @Input() inputFormData;

  showMoreSettingsToggle = false;
  showPasswordToggle = false;

  constructor() {
    super();
  }

  ngOnInit(): void {}

  toggleMoreSettings(event: Event): void {
    event.preventDefault();
    this.showMoreSettingsToggle = !this.showMoreSettingsToggle;
  }

  isMoreSettingsOpened(): boolean {
    return this.showMoreSettingsToggle;
  }
}
