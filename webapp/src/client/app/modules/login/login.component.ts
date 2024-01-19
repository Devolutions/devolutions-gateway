import {Component, OnInit} from '@angular/core';
import {FormGroup, FormControl, Validators} from '@angular/forms';

import {AuthService} from "@shared/services/auth.service";
import {NavigationService} from "@shared/services/navigation.service";
import {Observable, of} from "rxjs";
import {BaseComponent} from "@shared/bases/base.component";
import {catchError, switchMap, takeUntil} from "rxjs/operators";

@Component({
  selector: 'app-login',
  templateUrl: './login.component.html',
  styleUrls: ['./login.component.scss'],
})
export class LoginComponent extends BaseComponent implements OnInit {
  loginForm: FormGroup;

  constructor(private authService: AuthService,
              private navigationService: NavigationService) {
    super();
  }
  autoLoginAttempted: boolean = false;

  ngOnInit(): void {

    this.authService.isLoggedIn.pipe(
      takeUntil(this.destroyed$),
      switchMap((isLoggedIn) => this.callAutoLogin(isLoggedIn)),
      catchError((error) => this.handleAutoLoginError(error))
    ).subscribe(
      (success) => this.handleLoginResult(success)
    );

    this.loginForm = new FormGroup({
      username: new FormControl('', Validators.required),
      password: new FormControl('', Validators.required)
    });
  }

  onSubmit(): void {
    const submittedData = this.loginForm.value;

    this.authService.login(submittedData.username, submittedData.password).subscribe(
      (success) => {
        if (success) {
          this.navigationService.navigateToNewSession();
        } else {
          this.handleLoginError(new Error('Invalid username or password'));
        }
      },
      (error) => {
          this.handleLoginError(error);
      }
    );
  }

  private handleLoginResult(success: boolean) {
    if (success) {
      this.navigationService.navigateToNewSession();
    } else {
      this.autoLoginAttempted = true;
    }
  }

  private handleAutoLoginError(error: Error): Observable<boolean> {
    console.error('Error in Login init:', error);
    return of(false);
  }

  private callAutoLogin(isLoggedOn: boolean): Observable<boolean> {
    console.log('Already isLoggedOn?', isLoggedOn);
    if (!isLoggedOn) {
      return this.authService.autoLogin();
    } else {
      return of(true);
    }
  }

  private handleLoginError(error: Error): void {
    //TODO Send message to user
    console.error('Login Error', error);
  }
}
