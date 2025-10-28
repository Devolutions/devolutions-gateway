import { Component, Input, OnInit } from '@angular/core';
import { AbstractControl, FormGroup, ValidatorFn } from '@angular/forms';

import { BaseComponent } from '@shared/bases/base.component';
import { WebFormService } from '@shared/services/web-form.service';

@Component({
  selector: 'web-client-kdc-url-control',
  templateUrl: 'kdc-url-control.component.html',
  styleUrls: ['kdc-url-control.component.scss'],
})
export class KdcUrlControlComponent extends BaseComponent implements OnInit {
  @Input() parentForm: FormGroup;
  @Input() inputFormData;

  constructor(private formService: WebFormService) {
    super();
  }

  ngOnInit(): void {
    this.formService.addControlToForm({
      formGroup: this.parentForm,
      controlName: 'kdcUrl',
      inputFormData: this.inputFormData,
      isRequired: false,
      additionalValidator: this.kdcServerUrlValidator,
    });
  }

  kdcServerUrlValidator(): ValidatorFn {
    return (control: AbstractControl): { [key: string]: unknown } | null => {
      if (!control.value) {
        return null;
      }

      const validTcpProtocol: boolean = /^(tcp|udp):\/\/.*$/.test(control.value);
      return validTcpProtocol ? null : { invalidKdcProtocol: { value: control.value } };
    };
  }
}
