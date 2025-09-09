import { Component, Input, OnInit } from '@angular/core';
import { FormGroup } from '@angular/forms';

import { BaseComponent } from '@shared/bases/base.component';
import { WebFormService } from '@shared/services/web-form.service';

@Component({
  selector: 'web-client-jpeg-quality-level-control',
  templateUrl: 'jpeg-quality-level-control.component.html',
  styleUrls: ['jpeg-quality-level-control.component.scss'],
})
export class JpegQualityLevelControlComponent extends BaseComponent implements OnInit {
  @Input() parentForm: FormGroup;
  @Input() inputFormData;

  jpegEnabled = true;

  constructor(private formService: WebFormService) {
    super();
  }

  toggleCheckbox() {
    this.jpegEnabled = !this.jpegEnabled;
  }

  ngOnInit(): void {
    this.formService.addControlToForm({
      formGroup: this.parentForm,
      controlName: 'jpegEnabled',
      inputFormData: this.inputFormData,
      isRequired: false,
      defaultValue: true,
    });

    this.formService.addControlToForm({
      formGroup: this.parentForm,
      controlName: 'jpegQualityLevel',
      inputFormData: this.inputFormData,
      isRequired: false,
      defaultValue: 9,
    });
  }
}
