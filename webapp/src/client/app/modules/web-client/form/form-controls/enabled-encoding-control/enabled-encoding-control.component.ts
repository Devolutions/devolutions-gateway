import { Component, EventEmitter, Input, OnInit, Output } from '@angular/core';
import { FormGroup } from '@angular/forms';
import { Encoding } from '@gateway/shared/enums/encoding.enum';
import { BaseComponent } from '@shared/bases/base.component';
import { WebFormService } from '@shared/services/web-form.service';
import { SelectItem } from 'primeng/api';

@Component({
  selector: 'web-client-enabled-encoding-control',
  templateUrl: 'enabled-encoding-control.component.html',
  styleUrls: ['enabled-encoding-control.component.scss'],
})
export class EnabledEncodingControlComponent extends BaseComponent implements OnInit {
  @Input() parentForm: FormGroup;
  @Input() inputFormData;

  @Output() controlReady = new EventEmitter<void>();

  supportedEncodings: SelectItem[];

  constructor(private formService: WebFormService) {
    super();
  }

  ngOnInit(): void {
    this.supportedEncodings = this.formService.getSupportedEncodings();
    this.formService.addControlToForm({
      formGroup: this.parentForm,
      controlName: 'enabledEncoding',
      inputFormData: this.inputFormData,
      isRequired: false,
      defaultValue: Encoding.Default,
    });

    this.controlReady.emit();
  }
}
