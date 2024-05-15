import {
  AfterViewInit,
  Component,
  Injectable,
  Input,
  OnDestroy,
  OnInit,
} from '@angular/core';
import { FormGroup } from '@angular/forms';

import { BaseComponent } from '@shared/bases/base.component';
import { SelectItem } from 'primeng/api';
import { WebFormService } from '@gateway/shared/services/web-form.service';
import { map, startWith, switchMap, takeUntil, tap } from 'rxjs/operators';
import { SshAuthMode } from '@gateway/shared/enums/web-client-auth-mode.enum';
import { Observable, of } from 'rxjs';
import { SshKeyService } from '@gateway/shared/services/ssh-key.service';
import { ChangeDetectorRef } from '@angular/core';

interface FormInputVisibility {
  showPasswordInput?: boolean;
  showPrivateKeyInput?: boolean;
}

@Injectable({ providedIn: 'root' })
@Component({
  selector: 'ssh-form',
  templateUrl: 'ssh-form.component.html',
  styleUrls: ['ssh-form.component.scss'],
})
export class SshFormComponent
  extends BaseComponent
  implements OnInit, OnDestroy, AfterViewInit
{
  @Input() form: FormGroup;
  @Input() inputFormData: any;

  authModeOptions: SelectItem[];

  formInputVisibility: FormInputVisibility = {
    showPasswordInput: true,
    showPrivateKeyInput: false,
  };

  constructor(
    private formService: WebFormService,
    private sshKeyService: SshKeyService,
    private ChangeDetectorRef: ChangeDetectorRef
  ) {
    super();
  }

  ngAfterViewInit(): void {
    this.formService.canConnectIfAlsoTrue(() => {
      if (!this.formInputVisibility.showPrivateKeyInput) {
        return true;
      }

      return this.sshKeyService.hasValidPrivateKey();
    });
  }

  ngOnInit(): void {
    this.initializeFormOptions();
    this.addControlsToParentForm(this.inputFormData);
  }

  ngOnDestroy(): void {
    this.formService.resetCanConnectCallback();
  }

  private addControlsToParentForm(inputFormData?: any): void {
    if (this.form) {
      this.clearForm();

      this.formService.addControlToForm(
        this.form,
        'authMode',
        inputFormData,
        true,
        false,
        SshAuthMode.Username_and_Password);

      this.subscribeToAuthModeChanges();
    }
  }

  private clearForm(): void {
    if (this.form.contains('authMode')) {
      this.form.removeControl('authMode');
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
          console.error('Error fetching dropdown options', error),
      });
  }

  private subscribeToAuthModeChanges(): void {
    this.form
      .get('authMode')
      .valueChanges.pipe(
        takeUntil(this.destroyed$),
        startWith(this.form.get('authMode').value as SshAuthMode),
        switchMap((authMode) => this.getFormInputVisibility(authMode)),
        tap(()=>this.ChangeDetectorRef.detectChanges())
      )
      .subscribe({
        error: (error) => console.error('Error subscribing to auth mode changes', error)
      });
  }

  private getFormInputVisibility(
    authMode: SshAuthMode
  ): Observable<SshAuthMode> {
    return of(this.formInputVisibility).pipe(
      tap((visibility: FormInputVisibility) => {
        const authModeAsNumber: number = +authMode;

        visibility.showPasswordInput =
          authModeAsNumber === SshAuthMode.Username_and_Password;

        visibility.showPrivateKeyInput = authModeAsNumber === SshAuthMode.Private_Key;
      }),
      map(() => {
        return authMode;
      })
    );
  }

}
