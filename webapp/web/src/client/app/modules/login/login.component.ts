import {Component, OnInit} from '@angular/core';
import { FormGroup, FormControl, Validators } from '@angular/forms';

import { AuthService} from "@shared/services/auth.service";
import { NavigationService } from "@shared/services/navigation.service";
import {noop} from "rxjs";
import {BaseComponent} from "@shared/bases/base.component";

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

  ngOnInit(): void {
    this.loginForm = new FormGroup({
      username: new FormControl('', Validators.required),
      password: new FormControl('', Validators.required)
    });
  }

  onSubmit(): void {
    const submittedData = this.loginForm.value;

    this.authService.login(submittedData.username, submittedData.password).subscribe(() => {
      if (this.authService.isLoggedIn) {
        this.navigationService.navigateToNewSession().then(noop);
      }
    });
  }

  // login(): void {
  //   this.authService.login(this.username, this.password).subscribe(() => {
  //     if (this.authService.isLoggedIn) {
  //       this.navigationService.navigateToNewSession().then(noop);
  //     }
  //   });
  // }
}
