import { Component, Input, OnInit } from '@angular/core';
import { FormGroup } from '@angular/forms';

import { BaseComponent } from '@shared/bases/base.component';
import { WebFormService } from '@shared/services/web-form.service';
import { ArdQualityMode } from '@shared/enums/ard-quality-mode.enum';

@Component({
  selector: 'web-client-disable-cursor-control',
  templateUrl: 'disable-cursor-control.component.html',
  styleUrls: ['disable-cursor-control.component.scss'],
})
export class DisableCursorControlComponent extends BaseComponent implements OnInit {
  @Input() parentForm: FormGroup;
  @Input() inputFormData;

  constructor(private formService: WebFormService) {
    super();
  }

  ngOnInit(): void {
    this.formService.addControlToForm({
      formGroup: this.parentForm,
      controlName: 'disableCursor',
      inputFormData: this.inputFormData,
      isRequired: false,
      defaultValue: false,
    });
  }
}
