import {Component, OnInit} from '@angular/core';
import {FormGroup, FormControl, Validators} from '@angular/forms';

import {AuthService} from "@shared/services/auth.service";
import {NavigationService} from "@shared/services/navigation.service";
import {Observable, of} from "rxjs";
import {BaseComponent} from "@shared/bases/base.component";
import {catchError, takeUntil} from "rxjs/operators";
import {Message} from "primeng/api";
import {GatewayAlertMessageService} from "@shared/components/gateway-alert-message/gateway-alert-message.service";
import {UtilsService} from "@shared/services/utils.service";

@Component({
  selector: 'app-login',
  templateUrl: './login.component.html',
  styleUrls: ['./login.component.scss'],
})
export class LoginComponent extends BaseComponent implements OnInit {
  loginForm: FormGroup;
  messages: Message[] = [];

  constructor(private authService: AuthService,
              private navigationService: NavigationService,
              protected utils: UtilsService,
              private gatewayAlertMessageService: GatewayAlertMessageService) {
    super();
  }
  autoLoginAttempted: boolean = false;

  ngOnInit(): void {


    console.log(this.utils.string.extractDomain('user@example.com')); // Outputs: example.com
    // console.log(extractDomain('http://example.com')); // Outputs: example.com
    // console.log(extractDomain('example.com')); // Outputs: example.com

    this.authService.autoLogin().pipe(
      takeUntil(this.destroyed$),
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
    this.messages = [];
    const submittedData = this.loginForm.value;

    this.authService.login(submittedData.username, submittedData.password).subscribe(
      (success) => {
        if (success) {
          this.navigationService.navigateToNewSession();
        } else {
          // 'ConnectionErrorPleaseVerifyYourConnectionSettings'
          this.handleLoginError(new Error('Connection error: Please verify your connection settings.'));
        }
      },
      (error) => {
          this.handleLoginError(error);
      }
    );
  }

  private handleLoginResult(success: boolean): void {
    if (success) {
      this.navigationService.navigateToNewSession();
    } else {
      this.autoLoginAttempted = true;
    }
  }

  private handleAutoLoginError(error: Error): Observable<boolean> {
    if (error['status'] && error['status'] != '401') {
      console.error('Auto login:', error);
      this.addMessages([{
        severity: 'error',
        detail: error.message
      }]);
    }
    return of(false);
  }

  private handleLoginError(error: Error): void {
    let message: string = error.message;

    if (error['status'] && error['status'] === 401) {
      //For translation 'InvalidUserNameOrPasswordPleaseVerifyYourCredentials'
      message = "Invalid username or password, please verify your credentials";
    }
    this.addMessages([{
      severity: 'error',
      summary: 'Error', //For translation lblError
      detail: message
    }]);
    //this.gatewayAlertMessageService.addError(error.message);
    console.error('Login Error', error);
  }

  private addMessages(messages: Message[]) {
    this.messages = [];
    if (messages?.length > 0) {
      messages.forEach(message => {
        this.messages.push(message);
      })
    }
  }
}
