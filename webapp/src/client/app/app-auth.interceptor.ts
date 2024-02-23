import { Injectable } from '@angular/core';
import {HttpInterceptor, HttpRequest, HttpHandler, HttpEvent, HttpErrorResponse} from '@angular/common/http';
import {Observable, throwError} from 'rxjs';
import {AuthService} from "@shared/services/auth.service";
import {catchError} from "rxjs/operators";
import {Router} from "@angular/router";
import {NavigationService} from "@shared/services/navigation.service";

@Injectable()
export class AuthInterceptor implements HttpInterceptor {
  private readonly appTokenUrl: string = '/app-token';

  constructor(private authService: AuthService,
              private readonly router: Router,
              private navigationService: NavigationService) {
  }

  intercept(req: HttpRequest<any>, next: HttpHandler): Observable<HttpEvent<any>> {
    if (req.url.endsWith(this.appTokenUrl)) {
      return next.handle(req).pipe(
        catchError((error: HttpErrorResponse) => {
          //console.error('error', error)
          if (error.status === 401 || error.status === 407) {
            this.navigationService.navigateToLogin();
          }
          return throwError(error);
        })
      );
    }

    const authToken: string = this.authService.sessionValue.token;
    const authReq = authToken
      ? req.clone({ headers: req.headers.set('Authorization', `Bearer ${authToken}`) })
      : req;

    return next.handle(authReq).pipe(
      catchError((error: HttpErrorResponse) => {
        if (error.status === 401 || error.status === 407) {
          this.authService.logout();
        }
        return throwError(error);
      })
    );
  }
}
