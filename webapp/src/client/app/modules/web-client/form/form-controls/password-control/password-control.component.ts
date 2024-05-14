import {Component, Input, OnInit, SimpleChanges} from "@angular/core";
import {AbstractControl, FormGroup} from "@angular/forms";

import {BaseComponent} from "@shared/bases/base.component";
import {WebFormService} from "@shared/services/web-form.service";

@Component({
  selector: 'web-client-password-control',
  templateUrl: 'password-control.component.html',
  styleUrls: ['password-control.component.scss']
})
export class PasswordControlComponent extends BaseComponent implements  OnInit {

  @Input() parentForm: FormGroup;
  @Input() inputFormData: any;
  @Input() isEnabled: boolean = true;
  @Input() label: string = 'Password';
  @Input() formKey: string = 'password';

  showPasswordToggle: boolean = false;

  constructor(private formService: WebFormService) {
    super();
  }

  ngOnInit(): void {
    this.formService.addControlToForm(this.parentForm,this.formKey, this.inputFormData);
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
    const control: AbstractControl<any, any> = this.parentForm.get(this.formKey);
    if (control) {
      this.isEnabled ? control.enable() : control.disable();
    }
  }
}
