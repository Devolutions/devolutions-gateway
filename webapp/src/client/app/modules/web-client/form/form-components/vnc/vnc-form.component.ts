import { ChangeDetectorRef, Component, Input, OnInit } from '@angular/core';
import { FormGroup } from '@angular/forms';

import { BaseComponent } from '@shared/bases/base.component';
import { VncAuthMode } from '@shared/enums/web-client-auth-mode.enum';
import { WebFormService } from '@shared/services/web-form.service';
import { SelectItem } from 'primeng/api';
import { Observable, of } from 'rxjs';
import { map, startWith, switchMap, takeUntil, tap } from 'rxjs/operators';
import { UAParser } from 'ua-parser-js';

interface FormInputVisibility {
  showUsernameInput?: boolean;
  showPasswordInput?: boolean;
}

@Component({
  selector: 'vnc-form',
  templateUrl: 'vnc-form.component.html',
  styleUrls: ['vnc-form.component.scss'],
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
  showAutoClipboardCheckbox = false;

  constructor(
    private formService: WebFormService,
    private cdr: ChangeDetectorRef,
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

    this.showAutoClipboardCheckbox = new UAParser().getEngine().name === 'Blink';
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
