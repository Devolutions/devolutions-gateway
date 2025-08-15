import { Component, Input, OnInit, SimpleChanges } from '@angular/core';
import { FormGroup, ReactiveFormsModule, Validators } from '@angular/forms';

import { BaseComponent } from '@shared/bases/base.component';
import { WebFormService } from '@shared/services/web-form.service';

@Component({
  selector: 'web-client-password-control',
  templateUrl: 'password-control.component.html',
  styleUrls: ['password-control.component.scss'],
  standalone: true,
  imports: [ReactiveFormsModule],
})
export class PasswordControlComponent extends BaseComponent implements OnInit {
  @Input() parentForm: FormGroup;
  @Input() inputFormData;
  @Input() isEnabled = true;
  @Input() label = 'Password';
  @Input() formKey = 'password';
  @Input() isRequired = true;

  showPasswordToggle = false;

  constructor(private formService: WebFormService) {
    super();
  }

  ngOnInit(): void {
    console.log('this is required', this.isRequired);
    this.formService.addControlToForm({
      formGroup: this.parentForm,
      controlName: this.formKey,
      inputFormData: this.inputFormData,
      isRequired: this.isRequired,
    });
    this.toggleControl();
  }

  toggleShowPassword(): void {
    this.showPasswordToggle = !this.showPasswordToggle;
  }

  ngOnChanges(changes: SimpleChanges): void {
    if (changes.isEnabled) {
      this.toggleControl();
    }
  }

  private toggleControl(): void {
    const control = this.parentForm.get(this.formKey);
    if (control) {
      this.isEnabled ? control.enable() : control.disable();
    }
    this.updateValidators();
  }

  private updateValidators(): void {
    const control = this.parentForm.get(this.formKey);
    if (control) {
      if (this.isRequired) {
        control.setValidators([Validators.required]);
      } else {
        control.clearValidators(); // Remove the 'required' validator
      }
      control.updateValueAndValidity(); // Ensure the form reflects new validation state
    }
  }
}
