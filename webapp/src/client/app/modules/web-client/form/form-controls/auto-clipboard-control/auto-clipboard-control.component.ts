import { Component, Input, OnInit } from '@angular/core';
import { FormGroup } from '@angular/forms';

import { BaseComponent } from '@shared/bases/base.component';
import { WebFormService } from '@shared/services/web-form.service';

@Component({
  selector: 'web-client-auto-clipboard-control',
  templateUrl: 'auto-clipboard-control.component.html',
  styleUrls: ['auto-clipboard-control.component.scss'],
})
export class AutoClipboardControlComponent extends BaseComponent implements OnInit {
  @Input() parentForm: FormGroup;
  @Input() inputFormData;

  constructor(private formService: WebFormService) {
    super();
  }

  ngOnInit(): void {
    this.formService.addControlToForm({
      formGroup: this.parentForm,
      controlName: 'autoClipboard',
      inputFormData: this.inputFormData,
      isRequired: false,
      defaultValue: true,
    });
  }
}
