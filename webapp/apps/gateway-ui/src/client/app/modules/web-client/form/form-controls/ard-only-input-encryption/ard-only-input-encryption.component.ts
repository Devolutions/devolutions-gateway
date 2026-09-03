import { Component, Input, OnInit } from '@angular/core';
import { FormGroup } from '@angular/forms';

import { BaseComponent } from '@shared/bases/base.component';
import { WebFormService } from '@shared/services/web-form.service';

@Component({
  standalone: false,
  selector: 'web-client-ard-only-input-encryption-control',
  templateUrl: 'ard-only-input-encryption-control.component.html',
  styleUrls: ['ard-only-input-encryption.component.scss'],
})
export class ArdOnlyInputEncryptionComponent extends BaseComponent implements OnInit {
  @Input() parentForm: FormGroup;
  @Input() inputFormData;

  constructor(private formService: WebFormService) {
    super();
  }

  ngOnInit(): void {
    this.formService.addControlToForm({
      formGroup: this.parentForm,
      controlName: 'ardOnlyInputEncryption',
      inputFormData: this.inputFormData,
      isRequired: false,
      defaultValue: false,
    });
  }
}
