import { Injectable } from '@angular/core';
import { AdSessionManager, AdWebSessionConfig } from '@devolutions/web-active-directory-gui';
import { Observable, of, throwError } from 'rxjs';

@Injectable()
export class ActiveDirectorySessionManagerService implements AdSessionManager {
  private readonly sessionConfigMap = new Map<string, AdWebSessionConfig>();

  setWebSessionConfig(config: AdWebSessionConfig): void {
    this.sessionConfigMap.set(config.sessionId, config);
  }

  clearWebSessionConfig(sessionId: string): void {
    this.sessionConfigMap.delete(sessionId);
  }

  getWebSessionConfig(sessionId: string): Observable<AdWebSessionConfig> {
    const config = this.sessionConfigMap.get(sessionId);

    if (!config) {
      return throwError(() => new Error(`Active Directory session config not found for session ${sessionId}`));
    }

    return of(config);
  }
}
