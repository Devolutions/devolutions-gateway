import { Component, Input, OnInit } from '@angular/core';
import { FormGroup, ReactiveFormsModule } from '@angular/forms';
import { ArdFormDataInput } from '@gateway/shared/interfaces/forms.interfaces';

import { BaseComponent } from '@shared/bases/base.component';
import { ArdQualityModeControlComponent } from '../../form-controls/ard-quality-mode-control/ard-quality-mode-control.component';
import { PasswordControlComponent } from '../../form-controls/password-control/password-control.component';
import { ResolutionQualityControlComponent } from '../../form-controls/resolution-quality-control/resolution-quality-control.component';
import { UsernameControlComponent } from '../../form-controls/username-control/username-control.component';

@Component({
  selector: 'ard-form',
  templateUrl: 'ard-form.component.html',
  styleUrls: ['ard-form.component.scss'],
  standalone: true,
  imports: [
    ReactiveFormsModule,
    UsernameControlComponent,
    PasswordControlComponent,
    ResolutionQualityControlComponent,
    ArdQualityModeControlComponent,
  ],
})
export class ArdFormComponent extends BaseComponent implements OnInit {
  @Input() form: FormGroup;
  @Input() inputFormData: ArdFormDataInput;

  showMoreSettings = false;

  constructor() {
    super();
  }

  ngOnInit(): void {}

  toggleMoreSettings(event: Event): void {
    event.preventDefault();
    this.showMoreSettings = !this.showMoreSettings;
  }
}
