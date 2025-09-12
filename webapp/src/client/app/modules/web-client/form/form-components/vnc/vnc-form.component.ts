import { ChangeDetectorRef, Component, Input, OnInit } from '@angular/core';
import { FormGroup } from '@angular/forms';

import { BaseComponent } from '@shared/bases/base.component';
import { Encoding } from '@shared/enums/encoding.enum';
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

interface TightOptions {
  jpeg: boolean;
  png: boolean;
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
  showPixelFormatSelector = false;
  showTightOptions = false;
  showExtendedClipboardCheckbox = false;
  showAutoClipboardCheckbox = false;

  pixelFormatSelectorDisabled = false;

  selectedEncoding = Encoding.Default;
  tightOptions: TightOptions = { jpeg: true, png: true };

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

    this.showExtendedClipboardCheckbox =
      !!(navigator.clipboard.read && navigator.clipboard.write) && window.isSecureContext;
    this.showAutoClipboardCheckbox = new UAParser().getEngine().name === 'Blink' && window.isSecureContext;
  }

  subscribeToSelectedEncodingChanges(): void {
    this.form
      .get('enabledEncoding')
      .valueChanges.pipe(
        takeUntil(this.destroyed$),
        startWith(this.form.get('enabledEncoding').value as Encoding),
        switchMap((encoding: Encoding) => {
          this.showPixelFormatSelector = encoding !== Encoding.Default;
          this.showTightOptions = encoding === Encoding.Tight;
          this.selectedEncoding = encoding;

          return of(undefined);
        }),
      )
      .subscribe({
        error: (error) => console.error('Failed to subscribe to selected encoding changes', error),
      });
  }

  subscribeToJpegEnabledChanges(): void {
    this.form
      .get('jpegEnabled')
      .valueChanges.pipe(
        takeUntil(this.destroyed$),
        startWith(this.form.get('jpegEnabled').value as boolean),
        switchMap((jpegEnabled: boolean) => {
          this.tightOptions.jpeg = jpegEnabled;
          this.updatePixelFormatOptionState();
          this.cdr.detectChanges();

          return of(undefined);
        }),
      )
      .subscribe({
        error: (error) => console.error('Failed to subscribe to jpeg enabled changes', error),
      });
  }

  subscribeToPngEnabledChanges(): void {
    this.form
      .get('pngEnabled')
      .valueChanges.pipe(
        takeUntil(this.destroyed$),
        startWith(this.form.get('pngEnabled').value as boolean),
        switchMap((pngEnabled: boolean) => {
          this.tightOptions.png = pngEnabled;
          this.updatePixelFormatOptionState();
          this.cdr.detectChanges();

          return of(undefined);
        }),
      )
      .subscribe({
        error: (error) => console.error('Failed to subscribe to jpeg enabled changes', error),
      });
  }

  private updatePixelFormatOptionState(): void {
    const { jpeg, png } = this.tightOptions;

    // Disable PixelFormat option for Tight JPEG and Tight PNG.
    if (this.selectedEncoding === Encoding.Tight && (jpeg || png)) {
      this.pixelFormatSelectorDisabled = true;
      return;
    }

    this.pixelFormatSelectorDisabled = false;
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
