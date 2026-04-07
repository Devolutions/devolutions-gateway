import { Directive } from '@angular/core';
import { IronError, UserInteraction } from '@devolutions/iron-remote-desktop';
import { ClipboardActionButton } from '@shared/components/floating-session-toolbar/floating-session-toolbar.component';
import { GatewayAlertMessageService } from '@shared/components/gateway-alert-message/gateway-alert-message.service';
import { UAParser } from 'ua-parser-js';
import { AnalyticService } from '../services/analytic.service';
import { WebClientBaseComponent } from './base-web-client.component';

@Directive()
export abstract class DesktopWebClientBaseComponent extends WebClientBaseComponent {
  // ── Clipboard state — shared by desktop protocol components only ──────────
  protected remoteClient: UserInteraction;
  saveRemoteClipboardButtonEnabled = false;
  clipboardActionButtons: ClipboardActionButton[] = [];

  protected constructor(
    protected override gatewayAlertMessageService: GatewayAlertMessageService,
    protected override analyticService: AnalyticService,
  ) {
    super(gatewayAlertMessageService, analyticService);
  }

  /** True when the remote client should handle clipboard automatically.
   *  For form-based connections the explicit autoClipboard field is used.
   *  When autoClipboard is undefined (URL/config-based RDP connections) the
   *  Blink engine is used as a reliable heuristic. */
  protected isAutoClipboardMode(autoClipboard?: boolean): boolean {
    if (autoClipboard !== undefined) return autoClipboard;
    return new UAParser().getEngine().name === 'Blink';
  }

  /** Populates clipboardActionButtons for manual clipboard workflows.
   *  Call after the component knows whether auto-clipboard is enabled.
   *  No-ops when in a non-secure context or when auto-clipboard is active. */
  protected setupClipboardHandling(autoClipboard?: boolean): void {
    if (!window.isSecureContext || this.isAutoClipboardMode(autoClipboard)) {
      return;
    }

    this.clipboardActionButtons.push({
      label: 'Save Clipboard',
      tooltip: 'Copy received clipboard content to your local clipboard.',
      icon: 'dvl-icon dvl-icon-save',
      action: () => this.saveRemoteClipboard(),
      enabled: () => this.saveRemoteClipboardButtonEnabled,
    });

    if (navigator.clipboard.readText) {
      this.clipboardActionButtons.push({
        label: 'Send Clipboard',
        tooltip: 'Send your local clipboard content to the remote server.',
        icon: 'dvl-icon dvl-icon-send',
        action: () => this.sendClipboard(),
        enabled: () => true,
      });
    }
  }

  async saveRemoteClipboard(): Promise<void> {
    try {
      await this.remoteClient.saveRemoteClipboardData();
      this.webClientSuccess('Clipboard content has been copied to your clipboard!');
      this.saveRemoteClipboardButtonEnabled = false;
    } catch (err) {
      this.handleSessionError(err);
    }
  }

  async sendClipboard(): Promise<void> {
    try {
      await this.remoteClient.sendClipboardData();
      this.webClientSuccess('Clipboard content has been sent to the remote server!');
    } catch (err) {
      this.handleSessionError(err);
    }
  }

  protected handleSessionError(err: unknown): void {
    if (this.isIronError(err)) {
      this.webClientError(err.backtrace());
    } else {
      this.webClientError(`${err}`);
    }
  }

  protected isIronError(error: unknown): error is IronError {
    return (
      typeof error === 'object' &&
      error !== null &&
      typeof (error as IronError).backtrace === 'function' &&
      typeof (error as IronError).kind === 'function'
    );
  }
}

