import { Component, Input, OnInit } from '@angular/core';
import { FormGroup } from '@angular/forms';
import { BaseComponent } from '@shared/bases/base.component';
import { ArdControlModeLabels, ArdControlModes, DefaultArdStartMode } from '@shared/interfaces/ard-control.interfaces';
import { WebFormService } from '@shared/services/web-form.service';
import { SelectItem } from 'primeng/api';

@Component({
  standalone: false,
  selector: 'web-client-ard-start-mode-control',
  templateUrl: 'ard-start-mode-control.component.html',
})
export class ArdStartModeControlComponent extends BaseComponent implements OnInit {
  @Input() parentForm: FormGroup;
  @Input() inputFormData;

  readonly ardStartModeOptions: SelectItem[] = ArdControlModes.map((mode) => ({
    label: ArdControlModeLabels[mode],
    value: mode,
  }));

  constructor(private formService: WebFormService) {
    super();
  }

  ngOnInit(): void {
    this.formService.addControlToForm({
      formGroup: this.parentForm,
      controlName: 'ardStartMode',
      inputFormData: this.inputFormData,
      isRequired: false,
      defaultValue: DefaultArdStartMode,
    });
  }
}
