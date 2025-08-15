import { Component, Input, OnInit } from '@angular/core';
import { FormGroup, ReactiveFormsModule } from '@angular/forms';

import { BaseComponent } from '@shared/bases/base.component';
import { EnableDisplayConfigurationControlComponent } from '../../form-controls/enable-display-configuration-control/enable-display-configuration-control.component';
import { KdcUrlControlComponent } from '../../form-controls/kdc-url-control/kdc-url-control.component';
import { PasswordControlComponent } from '../../form-controls/password-control/password-control.component';
import { PreConnectionBlobControlComponent } from '../../form-controls/preconnection-blob/pre-connection-blob-control.component';
import { ScreenSizeControlComponent } from '../../form-controls/screen-size-control/screen-size-control.component';
import { UsernameControlComponent } from '../../form-controls/username-control/username-control.component';

@Component({
  selector: 'rdp-form',
  templateUrl: 'rdp-form.component.html',
  styleUrls: ['rdp-form.component.scss'],
  standalone: true,
  imports: [
    ReactiveFormsModule,
    UsernameControlComponent,
    PasswordControlComponent,
    ScreenSizeControlComponent,
    EnableDisplayConfigurationControlComponent,
    KdcUrlControlComponent,
    PreConnectionBlobControlComponent,
  ],
})
export class RdpFormComponent extends BaseComponent implements OnInit {
  @Input() form: FormGroup;
  @Input() inputFormData;

  showMoreSettingsToggle = false;
  showPasswordToggle = false;

  constructor() {
    super();
  }

  ngOnInit(): void {}

  toggleMoreSettings(event: Event): void {
    event.preventDefault();
    this.showMoreSettingsToggle = !this.showMoreSettingsToggle;
  }

  isMoreSettingsOpened(): boolean {
    return this.showMoreSettingsToggle;
  }
}
