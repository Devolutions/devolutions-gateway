import { Component, Input, OnInit } from '@angular/core';
import { FormGroup } from '@angular/forms';

import { BaseComponent } from '@shared/bases/base.component';
import { UAParser } from 'ua-parser-js';

@Component({
  standalone: false,
  selector: 'vnc-form',
  templateUrl: 'vnc-form.component.html',
  styleUrls: ['vnc-form.component.scss'],
})
export class VncFormComponent extends BaseComponent implements OnInit {
  @Input() form: FormGroup;
  @Input() inputFormData;

  showMoreSettings = false;
  showExtendedClipboardCheckbox = false;
  showAutoClipboardCheckbox = false;

  constructor() {
    super();
  }

  ngOnInit(): void {
    // Enable the extended clipboard option only if the modern Clipboard API is available (`read` and `write` methods).
    // But when running in non-secure contexts, `navigator.clipboard` is undefined, so we need to check the secure context first.
    this.showExtendedClipboardCheckbox =
      window.isSecureContext && !!(navigator.clipboard.read && navigator.clipboard.write);
    // Enable the auto clipboard option only for Blink-based browsers (e.g., Chrome, Edge) running in secure context.
    this.showAutoClipboardCheckbox = new UAParser().getEngine().name === 'Blink' && window.isSecureContext;
  }

  toggleMoreSettings(event: Event): void {
    event.preventDefault();
    this.showMoreSettings = !this.showMoreSettings;
  }
}
