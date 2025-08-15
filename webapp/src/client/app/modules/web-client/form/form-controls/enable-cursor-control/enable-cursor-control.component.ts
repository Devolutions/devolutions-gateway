import { Component, Input, OnInit } from '@angular/core';
import { FormGroup, ReactiveFormsModule } from '@angular/forms';

import { BaseComponent } from '@shared/bases/base.component';
import { WebFormService } from '@shared/services/web-form.service';
import { CheckboxModule } from 'primeng/checkbox';

@Component({
  selector: 'web-client-enable-cursor-control',
  templateUrl: 'enable-cursor-control.component.html',
  styleUrls: ['enable-cursor-control.component.scss'],
  standalone: true,
  imports: [ReactiveFormsModule, CheckboxModule],
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
