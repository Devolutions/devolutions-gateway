import { Component, Input, OnInit, SimpleChanges } from '@angular/core';
import { FormGroup } from '@angular/forms';

import { BaseComponent } from '@shared/bases/base.component';
import { WebFormService } from '@shared/services/web-form.service';

@Component({
  standalone: false,
  selector: 'web-client-username-control',
  templateUrl: 'username-control.component.html',
  styleUrls: ['username-control.component.scss'],
})
export class UsernameControlComponent extends BaseComponent implements OnInit {
  @Input() parentForm: FormGroup;
  @Input() inputFormData;
  @Input() isEnabled = true;

  constructor(private formService: WebFormService) {
    super();
  }

  ngOnInit(): void {
    this.formService.addControlToForm({
      formGroup: this.parentForm,
      controlName: 'username',
      inputFormData: this.inputFormData,
    });
    this.toggleControl();
  }

  ngOnChanges(changes: SimpleChanges): void {
    if (changes.isEnabled) {
      this.toggleControl();
    }
  }

  private toggleControl(): void {
    const control = this.parentForm.get('username');
    if (control) {
      this.isEnabled ? control.enable() : control.disable();
    }
  }
}
