import { HttpErrorResponse } from '@angular/common/http';
import { Component, OnInit } from '@angular/core';
import { FormControl, FormGroup, ReactiveFormsModule, Validators } from '@angular/forms';

import { BaseComponent } from '@shared/bases/base.component';
import { AuthService } from '@shared/services/auth.service';
import { NavigationService } from '@shared/services/navigation.service';
import { UtilsService } from '@shared/services/utils.service';
import { ToastMessageOptions } from 'primeng/api';
import { ButtonModule } from 'primeng/button';
import { MessageModule } from 'primeng/message';
import { Observable, of } from 'rxjs';
import { catchError, takeUntil } from 'rxjs/operators';

@Component({
  selector: 'app-login',
  templateUrl: './login.component.html',
  styleUrls: ['./login.component.scss'],
  standalone: true,
  imports: [ReactiveFormsModule, ButtonModule, MessageModule],
})
export class LoginComponent extends BaseComponent implements OnInit {
  loginForm: FormGroup;
  message: ToastMessageOptions = {};
  showPassword = false;
  autoLoginAttempted = false;

  constructor(
    private authService: AuthService,
    private navigationService: NavigationService,
    protected utils: UtilsService,
  ) {
    super();
  }

  ngOnInit(): void {
    this.authService
      .autoLogin()
      .pipe(
        takeUntil(this.destroyed$),
        catchError((error) => {
          this.handleAutoLoginError(error);
          return of(false);
        }),
      )
      .subscribe((success) => this.handleLoginResult(success));

    this.loginForm = new FormGroup({
      username: new FormControl('', Validators.required),
      password: new FormControl('', Validators.required),
    });
  }

  onSubmit(): void {
    this.message = {};
    const submittedData = this.loginForm.value;

    this.authService.login(submittedData.username, submittedData.password).subscribe({
      next: (success) => {
        if (success) {
          void this.navigationService.navigateToNewSession();
        } else {
          this.handleLoginError(new Error('Connection error: Please verify your connection settings.'));
        }
      },
      error: (error) => {
        this.handleLoginError(error);
      },
    });
  }

  toggleShowPassword(): void {
    this.showPassword = !this.showPassword;
  }

  private handleLoginResult(success: boolean): void {
    if (success) {
      void this.navigationService.navigateToReturnUrl();
    } else {
      this.autoLoginAttempted = true;
    }
  }

  private handleAutoLoginError(error: HttpErrorResponse): Observable<boolean> {
    if (error?.status !== 401) {
      console.error('Auto login:', error);
      this.addMessage({
        severity: 'error',
        detail: error.message,
      });
    }
    return of(false);
  }

  private handleLoginError(error): void {
    let message: string = error.message;

    if (error.status && error.status === 401) {
      //For translation 'InvalidUserNameOrPasswordPleaseVerifyYourCredentials'
      message = 'Invalid username or password, please verify your credentials';
    }
    this.addMessage({
      severity: 'error',
      summary: 'Error', //For translation lblError
      detail: message,
    });
    console.error('Login Error', error);
  }

  private addMessage(message: ToastMessageOptions) {
    this.message = {};
    if (message.text?.length > 0) {
      this.message = message;
    }
  }
}
