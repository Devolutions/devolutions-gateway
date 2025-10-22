import { Component, Input, OnInit } from '@angular/core';
import { FormControl, FormGroup } from '@angular/forms';

import { BaseComponent } from '@shared/bases/base.component';
import { WebFormService } from '@shared/services/web-form.service';

@Component({
  standalone: false,
  selector: 'web-client-enable-display-configuration-control',
  templateUrl: 'enable-display-configuration-control.component.html',
  styleUrls: ['enable-display-configuration-control.component.scss'],
})
export class EnableDisplayConfigurationControlComponent extends BaseComponent implements OnInit {
  @Input() parentForm: FormGroup;
  @Input() inputFormData;

  constructor(private formService: WebFormService) {
    super();
  }

  ngOnInit(): void {
    // Defensive: ensure parentForm exists
    if (!this.parentForm) {
      console.warn('EnableDisplayConfigurationControlComponent: parentForm not provided — creating a local form for safety.');
      this.parentForm = new FormGroup({
        enableDisplayControl: new FormControl(true)
      });
      return;
    }

    // If the control is already present, keep it
    if (this.parentForm.contains('enableDisplayControl')) {
      console.log('EnableDisplayConfigurationControlComponent: control already exists', this.parentForm.get('enableDisplayControl')?.value);
      return;
    }

    // Try to add via service (keep existing behavior), but verify it actually created the control.
    try {
      this.formService.addControlToForm({
        formGroup: this.parentForm,
        controlName: 'enableDisplayControl',
        inputFormData: this.inputFormData,
        isRequired: false,
        defaultValue: true,
      });
    } catch (err) {
      console.warn('formService.addControlToForm failed — falling back to direct add', err);
    }

    // If the service didn't add the control, add it directly as a boolean FormControl
    if (!this.parentForm.contains('enableDisplayControl')) {
      console.warn('EnableDisplayConfigurationControlComponent: service did not add control — adding fallback FormControl');
      this.parentForm.addControl('enableDisplayControl', new FormControl(true));
    }
  }
}
