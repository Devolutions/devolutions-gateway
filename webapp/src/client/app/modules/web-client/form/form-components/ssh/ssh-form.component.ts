import { ChangeDetectorRef, Component, Input, OnInit } from '@angular/core';
import { FormControl, FormGroup } from '@angular/forms';

import { BaseComponent } from '@shared/bases/base.component';
import { SelectItem } from 'primeng/api';
import { WebFormService } from '@gateway/shared/services/web-form.service';
import { map, startWith, switchMap, takeUntil, tap } from 'rxjs/operators';
import { SshAuthMode } from '@gateway/shared/enums/web-client-auth-mode.enum';
import { Observable, of } from 'rxjs';

interface FormInputVisibility {
  showUsernameInput?: boolean;
  showPasswordInput?: boolean;
  showPrivateKeyInput?: boolean;
}

@Component({
  selector: 'ssh-form',
  templateUrl: 'ssh-form.component.html',
  styleUrls: ['ssh-form.component.scss']
})
export class SshFormComponent extends BaseComponent implements OnInit {
  @Input() form: FormGroup;
  @Input() inputFormData: any;
  authModeOptions: SelectItem[];

  formInputVisibility: FormInputVisibility = {
    showUsernameInput: true,
    showPasswordInput: true,
    showPrivateKeyInput: false
  };

  constructor(private formService: WebFormService, private cdr: ChangeDetectorRef) {
    super();
  }

  ngOnInit(): void {
    this.initializeFormOptions();
    this.addControlsToParentForm(this.inputFormData);
  }

  private addControlsToParentForm(inputFormData?: any): void {
    if (this.form) {
      this.form.addControl('authMode', new FormControl(inputFormData?.authMode || SshAuthMode.Username_and_Password));
      this.subscribeToAuthModeChanges();
    }
  }


  private initializeFormOptions(): void {
    this.formService
      .getAuthModeOptions('ssh')
      .pipe(takeUntil(this.destroyed$))
      .subscribe({
        next: (authModeOptions) => {
          this.authModeOptions = authModeOptions;
        },
        error: (error) =>
          console.error('Error fetching dropdown options', error)
      });
  }

  private subscribeToAuthModeChanges(): void {
    this.form.get('authMode').valueChanges.pipe(
      takeUntil(this.destroyed$),
      startWith(this.form.get('authMode').value as SshAuthMode),
      switchMap((authMode) => this.getFormInputVisibility(authMode))
    ).subscribe(() => {
      // this.formService.detectFormChanges(this.cdr);
    });
  }

  private getFormInputVisibility(authMode: SshAuthMode): Observable<SshAuthMode> {
    return of(this.formInputVisibility).pipe(
      tap((visibility) => {
        visibility.showUsernameInput = authMode === SshAuthMode.Username_and_Password || authMode === SshAuthMode.Private_Key;
        visibility.showPasswordInput = authMode === SshAuthMode.Username_and_Password;
        visibility.showPrivateKeyInput = authMode === SshAuthMode.Private_Key;
      }),
      map(() => {
        return authMode;
      })
    );
  }
}
