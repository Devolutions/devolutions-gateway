import { Injectable } from '@angular/core';
import { HttpClient, HttpHeaders } from '@angular/common/http';
import { Observable, throwError } from "rxjs";
import { catchError, map } from 'rxjs/operators';

export type GetVersionResult = {
  id: string,
  hostname:string,
  version:string
}

interface VersionInfo {
  latestVersion?: string;
  downloadLink?: string;
}


@Injectable({
    providedIn: 'root'
})
export class ApiService {
  private appTokenApiUrl: string = '/jet/webapp/app-token';
  private sessionTokenApiURL: string = '/jet/webapp/session-token';
  private healthApiURL: string = '/jet/health';
  private devolutionProductApiURL: string = 'https://devolutions.net/products.htm';
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

  getLatestVersion(keysToFetch: string[] = ['Gateway.Version', 'Gateway.Url']): Observable<VersionInfo> {
    return this.http.get(this.devolutionProductApiURL, { responseType: 'text' }).pipe(
      map((response: string) => {
        const result = response
          .split('\n')
          .map((line) => line.split('='))
          .filter((keyValue) => keyValue.length === 2 && keysToFetch.includes(keyValue[0]))
          .reduce((acc, [key, value]) => ({ ...acc, [key]: value }), {});

        const latestVersion = result['Gateway.Version'];
        const downloadLink = result['Gateway.Url'];

        return { latestVersion, downloadLink } as VersionInfo;
      }),
      catchError((error) => {
        console.error('Failed to fetch version info', error);
        return throwError(() => new Error('Failed to fetch version info'));
      })
    );
  }
}
