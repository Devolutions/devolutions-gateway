import { Component, Input, OnInit } from '@angular/core';
import { FormGroup } from '@angular/forms';

import { BaseComponent } from '@shared/bases/base.component';
import { UAParser } from 'ua-parser-js';

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
  showAutoClipboardCheckbox = false;

  constructor() {
    super();
  }

  ngOnInit(): void {
    this.showAutoClipboardCheckbox = new UAParser().getEngine().name === 'Blink' && window.isSecureContext;
  }

  toggleMoreSettings(event: Event): void {
    event.preventDefault();
    this.showMoreSettingsToggle = !this.showMoreSettingsToggle;
  }

  isMoreSettingsOpened(): boolean {
    return this.showMoreSettingsToggle;
  }
}
