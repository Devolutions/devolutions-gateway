import { HttpErrorResponse, HttpHandler, HttpInterceptor, HttpRequest } from '@angular/common/http';
import { Injectable } from '@angular/core';
import { NavigationService } from '@shared/services/navigation.service';
import { throwError } from 'rxjs';
import { catchError } from 'rxjs/operators';

@Injectable()
export class AuthInterceptor implements HttpInterceptor {
  private readonly appTokenUrl: string = '/app-token';

  constructor(
    //private authService: AuthService,
    //private readonly router: Router,
    private navigationService: NavigationService,
  ) {}

  intercept<T>(req: HttpRequest<T>, next: HttpHandler) {
    // If the request is for the app token, we don't need to add the Authorization header
    const goToNext = [];
    goToNext.push(req.url.endsWith(this.appTokenUrl));

    // If the requesting third party host, we don't need to add the Authorization header
    try {
      const currentUrl = new URL(window.location.href);
      const targetUrl = new URL(req.url);
      goToNext.push(currentUrl.hostname !== targetUrl.hostname);
    } catch (_e) {
      // do nothing, the url is not valid, the req is for the same host
    }

    if (goToNext.filter((x) => x).length > 0) {
      return next.handle(req).pipe(
        catchError((error: HttpErrorResponse) => {
          if (error.status === 401 || error.status === 407) {
            void this.navigationService.navigateToLogin();
          }
          return throwError(error);
        }),
      );
    }

    const authToken: string = this.authService.sessionValue.token;
    const authReq = authToken ? req.clone({ headers: req.headers.set('Authorization', `Bearer ${authToken}`) }) : req;

    return next.handle(authReq).pipe(
      catchError((error: HttpErrorResponse) => {
        if (error.status === 401 || error.status === 407) {
          this.authService.logout();
        }
        return throwError(error);
      }),
    );
  }
}
