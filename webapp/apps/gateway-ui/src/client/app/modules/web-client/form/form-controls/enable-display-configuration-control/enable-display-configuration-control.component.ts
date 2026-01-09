import { Component, Input, OnInit } from '@angular/core';
import { FormGroup } from '@angular/forms';

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
    this.formService.addControlToForm({
      formGroup: this.parentForm,
      controlName: 'enableDisplayControl',
      inputFormData: this.inputFormData,
      isRequired: false,
      defaultValue: true,
    });
  }
}
