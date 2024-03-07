import { Injectable } from '@angular/core';
import { HttpClient, HttpHeaders } from '@angular/common/http';
import { Observable } from "rxjs";

export type GetVersionResult = {
  id: string,
  hostname:string,
  version:string
}

@Injectable({
    providedIn: 'root'
})
export class ApiService {
  private appTokenApiUrl: string = '/jet/webapp/app-token';
  private sessionTokenApiURL: string = '/jet/webapp/session-token';
  private healthApiURL: string = '/jet/health';
  constructor(private http: HttpClient) {}

  generateAppToken(username?: string, password?: string): Observable<any> {
    let headers = new HttpHeaders({
      'Content-Type': 'application/json',
      'x-requested-with': 'XMLHttpRequest'
    });

    if (username && password) {
      headers = new HttpHeaders({
        'Authorization': `Basic ${btoa(username + ':' + password)}`,
        'Content-Type': 'application/json',
        'x-requested-with': 'XMLHttpRequest'
      });
    } else {
      username = '';
    }

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

  getVersion(): Observable<GetVersionResult> {
    return this.http.get(this.healthApiURL,{
      headers : {
        "accept" : "application/json"
      }
    }) as Observable<GetVersionResult>;
  }

  getLatestVersion(): Observable<any> {
    return this.http.get(this.healthApiURL, {
      headers: {
        "accept": "application/json"
      }
    });
  }
}
