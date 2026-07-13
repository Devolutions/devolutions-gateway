import { Component, Input, OnInit } from '@angular/core';
import { AbstractControl, FormGroup, ValidatorFn } from '@angular/forms';
import { BaseComponent } from '@shared/bases/base.component';
import { ActiveDirectoryFormDataInput } from '@shared/interfaces/forms.interfaces';
import { DefaultLdapPort, DefaultLdapsPort } from '@shared/services/web-client.service';
import { WebFormService } from '@shared/services/web-form.service';
import { takeUntil } from 'rxjs/operators';

@Component({
  standalone: false,
  selector: 'active-directory-form',
  templateUrl: 'active-directory-form.component.html',
  styleUrls: ['active-directory-form.component.scss'],
})
export class ActiveDirectoryFormComponent extends BaseComponent implements OnInit {
  @Input() form: FormGroup;
  @Input() inputFormData: ActiveDirectoryFormDataInput;

  constructor(private formService: WebFormService) {
    super();
  }

  ngOnInit(): void {
    this.addControlsToParentForm();
    this.subscribeToLdapsChanges();
  }

  private addControlsToParentForm(): void {
    const useLdaps = this.inputFormData?.useLdaps ?? false;

    this.formService.addControlToForm({
      formGroup: this.form,
      controlName: 'domain',
      inputFormData: this.inputFormData,
      isRequired: false,
    });

    this.formService.addControlToForm({
      formGroup: this.form,
      controlName: 'port',
      inputFormData: this.inputFormData,
      isRequired: true,
      defaultValue: useLdaps ? DefaultLdapsPort : DefaultLdapPort,
      additionalValidator: this.portValidator(),
    });

    this.formService.addControlToForm({
      formGroup: this.form,
      controlName: 'useLdaps',
      inputFormData: this.inputFormData,
      isRequired: false,
      defaultValue: false,
    });

    this.formService.addControlToForm({
      formGroup: this.form,
      controlName: 'organizationalUnit',
      inputFormData: this.inputFormData,
      isRequired: false,
    });
  }

  private subscribeToLdapsChanges(): void {
    const useLdapsControl = this.form.get('useLdaps');
    const portControl = this.form.get('port');

    if (!useLdapsControl || !portControl) {
      return;
    }

    let previousDefaultPort = useLdapsControl.value ? DefaultLdapsPort : DefaultLdapPort;

    useLdapsControl.valueChanges.pipe(takeUntil(this.destroyed$)).subscribe((useLdaps: boolean) => {
      const nextDefaultPort = useLdaps ? DefaultLdapsPort : DefaultLdapPort;
      const currentPort = Number(portControl.value);

      if (currentPort === previousDefaultPort) {
        portControl.setValue(nextDefaultPort);
      }

      previousDefaultPort = nextDefaultPort;
    });
  }

  private portValidator(): ValidatorFn {
    return (control: AbstractControl): { [key: string]: unknown } | null => {
      const port = Number(control.value);

      if (!Number.isInteger(port) || port < 1 || port > 65535) {
        return { invalidPort: { value: control.value } };
      }

      return null;
    };
  }
}
