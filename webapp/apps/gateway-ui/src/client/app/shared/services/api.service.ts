import { HttpClient, HttpHeaders } from '@angular/common/http';
import { Injectable } from '@angular/core';
import { Observable, of, throwError } from 'rxjs';
import { catchError, map, switchMap, tap } from 'rxjs/operators';
import {
  AgentEnrollmentStringRequest,
  AgentEnrollmentStringResponse,
  AgentInfo,
} from '../interfaces/agent.interfaces';
import { SessionTokenParameters } from '../interfaces/connection-params.interfaces';

interface VersionInfo {
  latestVersion?: string;
  downloadLink?: string;
}

export type GetVersionResult = {
  id: string;
  hostname: string;
  version: string;
};

let VersionCache: GetVersionResult = null;

@Injectable({
  providedIn: 'root',
})
export class ApiService {
  private appTokenApiUrl = '/jet/webapp/app-token';
  private sessionTokenApiURL = '/jet/webapp/session-token';
  private healthApiURL = '/jet/health';
  private devolutionProductApiURL = 'https://devolutions.net/products.htm';
  private agentManagementTokenApiUrl = '/jet/webapp/agent-management-token';
  private agentsApiURL = '/jet/agent-tunnel/agents';
  private agentEnrollmentStringApiUrl = '/jet/agent-tunnel/enrollment-string';

  constructor(private http: HttpClient) {}

  generateAppToken(username?: string, password?: string) {
    let headers = new HttpHeaders({
      'Content-Type': 'application/json',
      'x-requested-with': 'XMLHttpRequest',
    });

    let finalUsername = username;
    if (username && password) {
      headers = new HttpHeaders({
        Authorization: `Basic ${btoa(username + ':' + password)}`,
        'Content-Type': 'application/json',
        'x-requested-with': 'XMLHttpRequest',
      });
    } else {
      finalUsername = '';
    }

    const body = {
      content_type: 'WEBAPP',
      subject: finalUsername,
      lifetime: 7200, // 2hours
    };

    return this.http.post(this.appTokenApiUrl, body, { headers, responseType: 'text' });
  }

  generateSessionToken(tokenParameters: SessionTokenParameters): Observable<string> {
    const headers: HttpHeaders = new HttpHeaders({
      'Content-Type': 'application/json',
    });

    return this.http.post(this.sessionTokenApiURL, tokenParameters, { headers, responseType: 'text' });
  }

  getVersion(): Observable<GetVersionResult> {
    if (VersionCache) {
      return of(VersionCache);
    }

    return this.http
      .get(this.healthApiURL, {
        headers: {
          accept: 'application/json',
        },
      })
      .pipe(
        tap((result: GetVersionResult) => {
          VersionCache = result;
        }),
      ) as Observable<GetVersionResult>;
  }

  getLatestVersion(keysToFetch: string[] = ['Gateway.Version', 'Gateway.Url']): Observable<VersionInfo> {
    return this.http
      .get(this.devolutionProductApiURL, {
        headers: {
          accept: 'text/plain',
        },
        responseType: 'text',
      })
      .pipe(
        map((response: string) => {
          const result = response
            .split('\n')
            .map((line) => line.split('='))
            .filter((keyValue) => keyValue.length === 2 && keysToFetch.includes(keyValue[0]))
            // biome-ignore lint/performance/noAccumulatingSpread: Not a performance concern
            .reduce((acc, [key, value]) => ({ ...acc, [key]: value }), {});

          const latestVersion = result['Gateway.Version'];
          const downloadLink = result['Gateway.Url'];

          return { latestVersion, downloadLink } as VersionInfo;
        }),
        catchError((error) => {
          console.error('Failed to fetch version info', error);
          return throwError(() => new Error('Failed to fetch version info'));
        }),
      );
  }

  /** Exchange the webapp app-token for a fresh agent management scope token. */
  private getAgentManagementToken(): Observable<string> {
    return this.http.post(this.agentManagementTokenApiUrl, {}, { responseType: 'text' });
  }

  private agentHeaders(): Observable<HttpHeaders> {
    return this.getAgentManagementToken().pipe(
      map(
        (token) =>
          new HttpHeaders({
            Authorization: `Bearer ${token}`,
            'Content-Type': 'application/json',
          }),
      ),
    );
  }

  listAgents(): Observable<AgentInfo[]> {
    return this.agentHeaders().pipe(
      switchMap((headers) => this.http.get<AgentInfo[]>(this.agentsApiURL, { headers })),
    );
  }

  getAgent(agentId: string): Observable<AgentInfo> {
    return this.agentHeaders().pipe(
      switchMap((headers) => this.http.get<AgentInfo>(`${this.agentsApiURL}/${agentId}`, { headers })),
    );
  }

  deleteAgent(agentId: string): Observable<void> {
    return this.agentHeaders().pipe(
      switchMap((headers) => this.http.delete<void>(`${this.agentsApiURL}/${agentId}`, { headers })),
    );
  }

  generateAgentEnrollmentString(
    request: AgentEnrollmentStringRequest,
  ): Observable<AgentEnrollmentStringResponse> {
    return this.agentHeaders().pipe(
      switchMap((headers) => this.http.post<AgentEnrollmentStringResponse>(this.agentEnrollmentStringApiUrl, request, { headers })),
    );
  }
}
