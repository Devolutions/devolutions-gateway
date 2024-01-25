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
          console.error('error', error)
          // Handle 401/407 errors for the app token request
          if (error.status === 401 || error.status === 407) {
            // Custom handling (e.g., redirect or display a message)
            // prevent default browser login prompt
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
        console.error('error', error)
        // Handle 401/407 errors for other requests
        if (error.status === 401 || error.status === 407) {
          // Custom handling (e.g., redirect or display a message)
          // prevent default browser login prompt
          return throwError(error);
        }
        return throwError(error);
      })
    );
  }

  //   if (req.url.endsWith(this.appTokenUrl)) {
  //     return next.handle(req);
  //   }
  //
  //   const authToken: string = this.authService.sessionValue.token;
  //
  //   const authReq = authToken
  //     ? req.clone({ headers: req.headers.set('Authorization', `Bearer ${authToken}`) })
  //     : req;
  //
  //   return next.handle(authReq);
  // }
}
