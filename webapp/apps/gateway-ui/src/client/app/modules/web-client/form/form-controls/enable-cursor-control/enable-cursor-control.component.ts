import { Component, Input, OnInit } from '@angular/core';
import { FormGroup } from '@angular/forms';

import { BaseComponent } from '@shared/bases/base.component';
import { WebFormService } from '@shared/services/web-form.service';

@Component({
  standalone: false,
  selector: 'web-client-enable-cursor-control',
  templateUrl: 'enable-cursor-control.component.html',
  styleUrls: ['enable-cursor-control.component.scss'],
})
export class EnableCursorControlComponent extends BaseComponent implements OnInit {
  @Input() parentForm: FormGroup;
  @Input() inputFormData;

  constructor(private formService: WebFormService) {
    super();
  }

  ngOnInit(): void {
    this.formService.addControlToForm({
      formGroup: this.parentForm,
      controlName: 'enableCursor',
      inputFormData: this.inputFormData,
      isRequired: false,
      defaultValue: true,
    });
  }
}
