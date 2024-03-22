import {ChangeDetectorRef, Component, Input, OnInit} from '@angular/core';
import {FormControl, FormGroup} from "@angular/forms";

import {BaseComponent} from "@shared/bases/base.component";
import {SelectItem} from "primeng/api";
import {map, startWith, switchMap, takeUntil, tap} from "rxjs/operators";
import {WebFormService} from "@shared/services/web-form.service";
import {AuthMode} from "@shared/enums/web-client-auth-mode.enum";
import {Observable, of} from "rxjs";

interface FormInputVisibility {
  showUsernameInput?: boolean;
  showPasswordInput?: boolean;
}

@Component({
  selector: 'vnc-form',
  templateUrl: 'vnc-form.component.html',
  styleUrls: ['vnc-form.component.scss']
})
export class VncFormComponent extends BaseComponent implements  OnInit {

  @Input() form: FormGroup;
  @Input() inputFormData: any;

  authModeOptions: SelectItem[];

  formInputVisibility: FormInputVisibility = {
    showUsernameInput: true,
    showPasswordInput: true
  };

  constructor(private formService: WebFormService,
              private cdr: ChangeDetectorRef) {
    super();
  }

  ngOnInit(): void {
    this.addControlsToParentForm(this.inputFormData);
    this.initializeFormOptions();
  }

  private addControlsToParentForm(inputFormData?: any): void {
    if (this.form) {
      this.form.addControl('authMode', new FormControl(inputFormData?.authMode || AuthMode.VNC_Password));
      this.subscribeToAuthModeChanges();
    }
  }

  showUsernameInput(): boolean {
    return this.formInputVisibility.showUsernameInput;
  }

  showPasswordInput(): boolean {
    return this.formInputVisibility.showPasswordInput;
  }

  private initializeFormOptions(): void {
    this.formService.getAuthModeOptions().pipe(
      takeUntil(this.destroyed$)
    ).subscribe({
      next: (authModeOptions) => {
        this.authModeOptions = authModeOptions;
      },
      error: (error) => console.error('Error fetching dropdown options', error)
    });
  }

  private subscribeToAuthModeChanges(): void {
    this.form.get('authMode').valueChanges.pipe(
      startWith(this.form.get('authMode').value as AuthMode),
      takeUntil(this.destroyed$),
      switchMap((authMode) => this.getFormInputVisibility(authMode))
    ).subscribe(() => {
      this.formService.detectFormChanges(this.cdr);
    });
  }

  private getFormInputVisibility(authMode: AuthMode): Observable<AuthMode> {
    return of(this.formInputVisibility).pipe(
      tap((visibility) => {
        if (authMode === 0) {
          visibility.showUsernameInput = false;
          visibility.showPasswordInput = false;
        } else {
          visibility.showUsernameInput = authMode === AuthMode.Username_and_Password;
          visibility.showPasswordInput = [AuthMode.VNC_Password, AuthMode.Username_and_Password].includes(authMode);
        }
      }),
      map(() => {
        return authMode;
      })
    );
  }
}
