import { ChangeDetectorRef, Component, Input, OnDestroy } from '@angular/core';
import { FormsModule } from '@angular/forms';
import type { CredentialsRequirement } from '@devolutions/iron-remote-desktop-vnc';
import { Button } from 'primeng/button';
import { Dialog } from 'primeng/dialog';
import { InputText } from 'primeng/inputtext';

export interface Credentials {
  username?: string;
  password?: string;
}

/** Rejection of a credentials request the user dismissed. */
export class CredentialsPromptCancelledError extends Error {
  constructor() {
    super('Credentials prompt cancelled');
    this.name = 'CredentialsPromptCancelledError';
  }
}

/** Dialog asking the user for the credentials a server requests while connecting. */
@Component({
  selector: 'credentials-prompt',
  standalone: true,
  imports: [FormsModule, Dialog, Button, InputText],
  templateUrl: 'credentials-prompt.component.html',
  styleUrls: ['credentials-prompt.component.scss'],
})
export class CredentialsPromptComponent implements OnDestroy {
  @Input({ required: true }) appendTo!: HTMLElement;

  visible = false;
  host = '';
  askUsername = false;
  askPassword = false;
  username = '';
  password = '';
  showPassword = false;

  private pending?: { resolve: (credentials: Credentials) => void; reject: (error: Error) => void };
  private destroyed = false;

  constructor(private cdr: ChangeDetectorRef) {}

  /**
   * Shows the dialog for `host`.
   * Rejects with `CredentialsPromptCancelledError` when the user dismisses it, and with a plain `Error` on a newer request or when the component is destroyed.
   */
  request(requirement: CredentialsRequirement, host: string): Promise<Credentials> {
    if (this.destroyed) {
      return Promise.reject(new Error('Credentials prompt destroyed'));
    }

    this.settle()?.reject(new Error('A newer credentials request replaced this one'));

    switch (requirement) {
      case 'username':
        this.askUsername = true;
        this.askPassword = false;
        break;
      case 'password':
        this.askUsername = false;
        this.askPassword = true;
        break;
      case 'username-and-password':
        this.askUsername = true;
        this.askPassword = true;
        break;
      default: {
        const unknown: never = requirement;
        return Promise.reject(new Error(`Unsupported credentials requirement: ${unknown}`));
      }
    }

    this.host = host;
    this.visible = true;
    this.cdr.detectChanges();

    return new Promise((resolve, reject) => {
      this.pending = { resolve, reject };
    });
  }

  canSubmit(): boolean {
    return (!this.askUsername || this.username !== '') && (!this.askPassword || this.password !== '');
  }

  submit(): void {
    if (!this.canSubmit()) {
      return;
    }

    const credentials: Credentials = {
      username: this.askUsername ? this.username : undefined,
      password: this.askPassword ? this.password : undefined,
    };
    this.settle()?.resolve(credentials);
  }

  // UNTESTED: every way the prompt goes away (Cancel, close button, Escape, a newer request, destroy) settles the pending request, and a request after destroy rejects at once.
  // The client waits on it with no timeout, so an unsettled request leaves the connection hanging behind a hidden prompt.
  // Settle the request on any new close path; user dismissals go through cancel().
  // A call after submit() is a no-op because settle() already cleared the request.
  cancel(): void {
    this.settle()?.reject(new CredentialsPromptCancelledError());
  }

  ngOnDestroy(): void {
    this.destroyed = true;
    this.settle()?.reject(new Error('Credentials prompt destroyed'));
  }

  /** Clears the dialog and returns the pending request, if any; callers settle it. */
  // UNTESTED: settling clears the typed username and password, so no secret outlives its request on any close path.
  // Keep the clears here rather than in individual handlers.
  private settle(): typeof this.pending {
    const pending = this.pending;
    this.pending = undefined;
    this.visible = false;
    this.username = '';
    this.password = '';
    this.showPassword = false;
    return pending;
  }
}
