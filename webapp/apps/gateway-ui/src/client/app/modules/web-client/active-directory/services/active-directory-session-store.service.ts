import { Injectable } from '@angular/core';
import { LdapSessionLike } from '@devolutions/web-active-directory-gui';

@Injectable()
export class ActiveDirectorySessionStoreService {
  private session: LdapSessionLike | null = null;

  setSession(session: LdapSessionLike): void {
    this.session = session;
  }

  getSession(): LdapSessionLike {
    if (!this.session) {
      throw new Error('No active LDAP session');
    }

    return this.session;
  }

  clearSession(): void {
    this.session = null;
  }
}
