import { Component, Input, OnInit } from '@angular/core';
import { FormGroup } from '@angular/forms';
import { ResolutionQuality } from '@gateway/shared/enums/resolution-quality.enum';
import { BaseComponent } from '@shared/bases/base.component';
import { WebFormService } from '@shared/services/web-form.service';
import { SelectItem } from 'primeng/api';

@Component({
  selector: 'web-client-resolution-quality-control',
  templateUrl: 'resolution-quality-control.component.html',
  styleUrls: ['resolution-quality-control.component.scss'],
})
export class ResolutionQualityControlComponent extends BaseComponent implements OnInit {
  @Input() parentForm: FormGroup;
  @Input() inputFormData;

  resolutionQualityOptions: SelectItem[];

  constructor(private formService: WebFormService) {
    super();
  }

  ngOnInit(): void {
    this.resolutionQualityOptions = this.formService.getResolutionQualityOptions();
    this.formService.addControlToForm({
      formGroup: this.parentForm,
      controlName: 'resolutionQuality',
      inputFormData: this.inputFormData,
      isRequired: false,
      defaultValue: ResolutionQuality.High,
    });
  }
}
