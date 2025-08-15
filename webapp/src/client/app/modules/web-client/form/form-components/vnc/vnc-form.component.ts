import { Component, Input, OnInit } from '@angular/core';
import { FormGroup, ReactiveFormsModule } from '@angular/forms';

import { BaseComponent } from '@shared/bases/base.component';
import { VncAuthMode } from '@shared/enums/web-client-auth-mode.enum';
import { WebFormService } from '@shared/services/web-form.service';
import { SelectItem } from 'primeng/api';
import { SelectModule } from 'primeng/select';
import { Observable, of } from 'rxjs';
import { map, startWith, switchMap, takeUntil, tap } from 'rxjs/operators';
import { EnableCursorControlComponent } from '../../form-controls/enable-cursor-control/enable-cursor-control.component';
import { EnabledEncodingsControlComponent } from '../../form-controls/enabled-encodings-control/enabled-encodings-control.component';
import { ExtendedClipboardControlComponent } from '../../form-controls/extended-clipboard-control/extended-clipboard-control.component';
import { PasswordControlComponent } from '../../form-controls/password-control/password-control.component';
import { ScreenSizeControlComponent } from '../../form-controls/screen-size-control/screen-size-control.component';
import { UltraVirtualDisplayControlComponent } from '../../form-controls/ultra-virtual-display-control/ultra-virtual-display-control.component';
import { UsernameControlComponent } from '../../form-controls/username-control/username-control.component';

interface FormInputVisibility {
  showUsernameInput?: boolean;
  showPasswordInput?: boolean;
}

@Component({
  selector: 'vnc-form',
  templateUrl: 'vnc-form.component.html',
  styleUrls: ['vnc-form.component.scss'],
  standalone: true,
  imports: [
    ReactiveFormsModule,
    SelectModule,
    UsernameControlComponent,
    PasswordControlComponent,
    ScreenSizeControlComponent,
    UltraVirtualDisplayControlComponent,
    EnabledEncodingsControlComponent,
    EnableCursorControlComponent,
    ExtendedClipboardControlComponent,
  ],
})
export class VncFormComponent extends BaseComponent implements OnInit {
  @Input() form: FormGroup;
  @Input() inputFormData;

  authModeOptions: SelectItem[];

  formInputVisibility: FormInputVisibility = {
    showUsernameInput: true,
    showPasswordInput: true,
  };

  showMoreSettings = false;

  constructor(
    private formService: WebFormService,
    //private cdr: ChangeDetectorRef,
  ) {
    super();
  }

  ngOnInit(): void {
    this.addControlsToParentForm(this.inputFormData);
    this.initializeFormOptions();
  }

  private addControlsToParentForm(inputFormData?): void {
    if (this.form) {
      this.clearForm();

      this.formService.addControlToForm({
        formGroup: this.form,
        controlName: 'authMode',
        inputFormData,
        isRequired: true,
        defaultValue: VncAuthMode.VNC_Password,
      });

      this.subscribeToAuthModeChanges();
    }
  }

  private clearForm(): void {
    if (this.form.contains('authMode')) {
      this.form.removeControl('authMode');
    }
  }

  showUsernameInput(): boolean {
    return this.formInputVisibility.showUsernameInput;
  }

  showPasswordInput(): boolean {
    return this.formInputVisibility.showPasswordInput;
  }

  toggleMoreSettings(event: Event): void {
    event.preventDefault();
    this.showMoreSettings = !this.showMoreSettings;
  }

  private initializeFormOptions(): void {
    this.formService
      .getAuthModeOptions('vnc')
      .pipe(takeUntil(this.destroyed$))
      .subscribe({
        next: (authModeOptions) => {
          this.authModeOptions = authModeOptions;
        },
        error: (error) => console.error('Error fetching dropdown options', error),
      });
  }

  private subscribeToAuthModeChanges(): void {
    this.form
      .get('authMode')
      .valueChanges.pipe(
        takeUntil(this.destroyed$),
        startWith(this.form.get('authMode').value as VncAuthMode),
        switchMap((authMode) => this.getFormInputVisibility(authMode)),
      )
      .subscribe({
        error: (error) => console.error('Error subscribing to auth mode changes', error),
      });
  }

  private getFormInputVisibility(authMode: VncAuthMode): Observable<VncAuthMode> {
    return of(this.formInputVisibility).pipe(
      tap((visibility: FormInputVisibility) => {
        const authModeAsNumber: number = +authMode;

        visibility.showUsernameInput = authModeAsNumber === VncAuthMode.Username_and_Password;
        visibility.showPasswordInput = [VncAuthMode.VNC_Password, VncAuthMode.Username_and_Password].includes(
          authModeAsNumber,
        );
      }),
      map(() => {
        return authMode;
      }),
    );
  }
}
