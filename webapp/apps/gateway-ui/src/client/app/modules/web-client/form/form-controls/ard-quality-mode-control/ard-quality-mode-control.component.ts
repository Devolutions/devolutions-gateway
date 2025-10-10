import { Component, Input, OnInit } from '@angular/core';
import { FormGroup } from '@angular/forms';
import { ArdQualityMode } from '@gateway/shared/enums/ard-quality-mode.enum';
import { BaseComponent } from '@shared/bases/base.component';
import { WebFormService } from '@shared/services/web-form.service';
import { SelectItem } from 'primeng/api';

@Component({
  selector: 'web-client-ard-quality-mode-control',
  templateUrl: 'ard-quality-mode-control.component.html',
  styleUrls: ['ard-quality-mode-control.component.scss'],
})
export class ArdQualityModeControlComponent extends BaseComponent implements OnInit {
  @Input() parentForm: FormGroup;
  @Input() inputFormData;

  ardQualityModeOptions: SelectItem[];

  constructor(private formService: WebFormService) {
    super();
  }

  ngOnInit(): void {
    this.ardQualityModeOptions = this.formService.getArdQualityModeOptions();
    this.formService.addControlToForm({
      formGroup: this.parentForm,
      controlName: 'ardQualityMode',
      inputFormData: this.inputFormData,
      isRequired: false,
      defaultValue: ArdQualityMode.Adaptive,
    });
  }
}
