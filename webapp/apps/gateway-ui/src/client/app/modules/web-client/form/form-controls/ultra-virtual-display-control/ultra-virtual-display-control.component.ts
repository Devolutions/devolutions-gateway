import { Component, Input, OnInit } from '@angular/core';
import { FormGroup } from '@angular/forms';

import { BaseComponent } from '@shared/bases/base.component';
import { WebFormService } from '@shared/services/web-form.service';

@Component({
  standalone: false,
  selector: 'web-client-ultra-virtual-display-control',
  templateUrl: 'ultra-virtual-display-control.component.html',
  styleUrls: ['ultra-virtual-display-control.component.scss'],
})
export class UltraVirtualDisplayControlComponent extends BaseComponent implements OnInit {
  @Input() parentForm: FormGroup;
  @Input() inputFormData;

  constructor(private formService: WebFormService) {
    super();
  }

  ngOnInit(): void {
    this.formService.addControlToForm({
      formGroup: this.parentForm,
      controlName: 'ultraVirtualDisplay',
      inputFormData: this.inputFormData,
      isRequired: false,
      defaultValue: false,
    });
  }
}
