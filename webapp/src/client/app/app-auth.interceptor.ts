import { Injectable } from '@angular/core';
import { HttpInterceptor, HttpRequest, HttpHandler, HttpEvent } from '@angular/common/http';
import { Observable } from 'rxjs';

@Injectable()
export class AuthInterceptor implements HttpInterceptor {
  private readonly appTokenUrl: string = '/app-token';

  intercept(req: HttpRequest<any>, next: HttpHandler): Observable<HttpEvent<any>> {
    if (req.url.endsWith(this.appTokenUrl)) {
      return next.handle(req);
    }

    const authToken: string = localStorage.getItem('appToken');

    const authReq = authToken
      ? req.clone({ headers: req.headers.set('Authorization', `Bearer ${authToken}`) })
      : req;

    return next.handle(authReq);
  }
}
