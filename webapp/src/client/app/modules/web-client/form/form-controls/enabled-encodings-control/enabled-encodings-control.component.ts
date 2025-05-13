import { Component, Input, OnInit } from '@angular/core';
import { FormGroup } from '@angular/forms';
import { SelectItem } from 'primeng/api';

import { BaseComponent } from '@shared/bases/base.component';
import { WebFormService } from '@shared/services/web-form.service';
import { Encoding } from '@gateway/shared/enums/encoding.enum';

@Component({
  selector: 'web-client-enabled-encodings-control',
  templateUrl: 'enabled-encodings-control.component.html',
  styleUrls: ['enabled-encodings-control.component.scss'],
})
export class EnabledEncodingsControlComponent extends BaseComponent implements OnInit {
  @Input() parentForm: FormGroup;
  @Input() inputFormData;

  supportedEncodings: SelectItem[];

  constructor(private formService: WebFormService) {
    super();
  }

  ngOnInit(): void {
    this.supportedEncodings = this.formService.getSupportedEncodings();
    this.formService.addControlToForm({
      formGroup: this.parentForm,
      controlName: 'enabledEncodings',
      inputFormData: this.inputFormData,
      isRequired: false,
      defaultValue: Encoding.getAllEncodings(),
    });
  }
}
