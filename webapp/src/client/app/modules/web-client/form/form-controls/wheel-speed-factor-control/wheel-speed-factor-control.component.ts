import { Component, Input, OnInit } from '@angular/core';
import { FormGroup } from '@angular/forms';

import { BaseComponent } from '@shared/bases/base.component';
import { WebFormService } from '@shared/services/web-form.service';

@Component({
  selector: 'web-client-wheel-speed-factor-control',
  templateUrl: 'wheel-speed-factor-control.component.html',
  styleUrls: ['wheel-speed-factor-control.component.scss'],
})
export class WheelSpeedFactorControlComponent extends BaseComponent implements OnInit {
  @Input() parentForm: FormGroup;
  @Input() inputFormData;

  constructor(private formService: WebFormService) {
    super();
  }

  ngOnInit(): void {
    this.formService.addControlToForm({
      formGroup: this.parentForm,
      controlName: 'wheelSpeedFactor',
      inputFormData: this.inputFormData,
      isRequired: false,
      defaultValue: 1.0,
    });
  }
}
