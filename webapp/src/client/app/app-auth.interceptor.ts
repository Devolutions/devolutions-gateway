import { Injectable } from '@angular/core';
import { HttpInterceptor, HttpRequest, HttpHandler, HttpEvent } from '@angular/common/http';
import { Observable } from 'rxjs';
import {AuthService} from "@shared/services/auth.service";

@Injectable()
export class AuthInterceptor implements HttpInterceptor {
  private readonly appTokenUrl: string = '/app-token';

  constructor(private authService: AuthService) {
  }

  intercept(req: HttpRequest<any>, next: HttpHandler): Observable<HttpEvent<any>> {
    if (req.url.endsWith(this.appTokenUrl)) {
      return next.handle(req);
    }

    const authToken: string = this.authService.sessionValue.token;

    const authReq = authToken
      ? req.clone({ headers: req.headers.set('Authorization', `Bearer ${authToken}`) })
      : req;

    return next.handle(authReq);
  }
}
