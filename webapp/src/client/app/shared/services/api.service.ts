import { Injectable } from '@angular/core';
import { HttpClient, HttpHeaders } from '@angular/common/http';
import { Observable } from "rxjs";

@Injectable({
    providedIn: 'root'
})
export class ApiService {
  private appTokenApiUrl: string = '/jet/webapp/app-token';
  private sessionTokenApiURL: string = '/jet/webapp/session-token';
  constructor(private http: HttpClient) {}

  generateAppToken(username: string, password: string): Observable<any> {
    const headers: HttpHeaders = new HttpHeaders({
      'Authorization': `Basic ${btoa(username + ':' + password)}`,
      'Content-Type': 'application/json'
    });

    const body = {
      content_type: 'WEBAPP',
      subject: username,
      lifetime: 7200 // 2hours
    };

    return this.http.post(this.appTokenApiUrl, body, { headers, responseType: 'text' });
  }

  generateSessionToken(tokenParameters: any): Observable<string> {
    const headers: HttpHeaders = new HttpHeaders({
      'Content-Type': 'application/json'
    });

    return this.http.post(this.sessionTokenApiURL, tokenParameters, { headers, responseType: 'text' });
  }

}
