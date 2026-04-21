import { Directive } from '@angular/core';
import { ToolbarSessionInfo } from '@shared/components/floating-session-toolbar/models/session-info.model';
import { GatewayAlertMessageService } from '@shared/components/gateway-alert-message/gateway-alert-message.service';
import { ComponentStatus } from '@shared/models/component-status.model';
import { ToastMessageOptions } from 'primeng/api';
import { BaseSessionComponent } from '../models/web-session.model';
import { AnalyticService, ConnectionIdentifier, ProtocolString } from '../services/analytic.service';

export interface WebComponentReady {
  webComponentReady(event: Event, webSessionId: string): void;
}

@Directive()
export abstract class WebClientBaseComponent extends BaseSessionComponent {
  hideSpinnerOnly = false;
  error: string;
  loading = true;
  sessionTerminationMessage: ToastMessageOptions;

  analyticHandle: ConnectionIdentifier;

  currentStatus: ComponentStatus = {
    id: undefined,
    isInitialized: false,
    isDisabled: false,
    isDisabledByUser: false,
  };

  // ── Toolbar session-info state ─────────────────────────────────────────────
  // Shared by all protocol components (SSH, Telnet, RDP, VNC, ARD).
  // Subclasses populate sessionInfoUrl / sessionInfoUsername and call
  // refreshSessionInfo(); the toolbar binds to sessionInfo.
  sessionInfo: ToolbarSessionInfo = { rows: [], emptyValueText: 'N/A' };
  protected sessionInfoUrl: string | null = null;
  protected sessionInfoUsername: string | null = null;
  private lastSessionInfoKey = '';

  protected constructor(
    protected gatewayAlertMessageService: GatewayAlertMessageService,
    protected analyticService: AnalyticService,
  ) {
    super();
  }

  // ── Session lifecycle helpers ──────────────────────────────────────────────

  //For translation 'ConnectionSuccessful
  protected webClientConnectionSuccess(message = 'Connection successful'): void {
    this.hideSpinnerOnly = true;
    this.gatewayAlertMessageService.addSuccess(message);
    this.analyticHandle = this.analyticService.sendOpenEvent(this.getProtocol());
  }

  protected webClientSuccess(message: string): void {
    this.gatewayAlertMessageService.addSuccess(message);
  }

  protected webClientError(errorMessage: string): void {
    this.gatewayAlertMessageService.addError(errorMessage);
    console.error(errorMessage);
  }

  protected webClientWarning(message: string): void {
    this.gatewayAlertMessageService.addWarning(message);
    console.warn(message);
  }

  protected webClientConnectionClosed(): void {
    if (this.analyticHandle) {
      this.analyticService.sendCloseEvent(this.analyticHandle);
    }
  }

  protected getGatewayWebSocketUrl(baseUrl: string, sessionId?: string): string {
    const normalizedBasePath = baseUrl.replace(/\/+$/, '');
    const path = sessionId ? `${normalizedBasePath}/${sessionId}` : normalizedBasePath;
    const gatewayUrl: URL = new URL(path, window.location.href);

    gatewayUrl.protocol = gatewayUrl.protocol === 'https:' ? 'wss:' : 'ws:';
    return gatewayUrl.toString();
  }

  // ── Session info helpers ───────────────────────────────────────────────────
  // Shared across all protocol components. Subclasses set sessionInfoUrl /
  // sessionInfoUsername then call refreshSessionInfo() to push a new snapshot
  // to the toolbar only when something actually changed.

  /**
   * Converts a WebSocket gateway URL to its HTTP/HTTPS equivalent for display.
   * Strips query params and hash so the URL shown in the session-info popover
   * is clean and does not expose one-time tokens.
   */
  protected toUserFacingUrl(url: string | null | undefined): string | null {
    if (!url) {
      return null;
    }
    try {
      const normalized = new URL(url, window.location.href);
      normalized.protocol = normalized.protocol === 'wss:' ? 'https:' : 'http:';
      normalized.search = '';
      normalized.hash = '';
      return normalized.toString();
    } catch {
      return url;
    }
  }

  /**
   * Builds the ToolbarSessionInfo snapshot from the current state.
   * Override in a subclass to add protocol-specific rows.
   */
  protected buildSessionInfo(): ToolbarSessionInfo {
    return {
      rows: [
        { id: 'sessionId', label: 'Session ID', value: this.webSessionId, monospace: true, order: 1 },
        { id: 'url', label: 'URL', value: this.sessionInfoUrl, monospace: true, order: 2 },
        {
          id: 'username',
          label: 'Username',
          value: this.sessionInfoUsername,
          hidden: !this.sessionInfoUsername,
          order: 3,
        },
      ],
      emptyValueText: 'N/A',
    };
  }

  /**
   * Updates sessionInfo only when the content has actually changed.
   * Call after updating sessionInfoUrl or sessionInfoUsername.
   */
  protected refreshSessionInfo(): void {
    const next = this.buildSessionInfo();
    const nextKey = this.buildSessionInfoKey(next);
    if (nextKey === this.lastSessionInfoKey) {
      return;
    }
    this.lastSessionInfoKey = nextKey;
    this.sessionInfo = next;
  }

  private buildSessionInfoKey(info: ToolbarSessionInfo): string {
    const rows = [...info.rows].sort(
      (a, b) => (a.order ?? Number.MAX_SAFE_INTEGER) - (b.order ?? Number.MAX_SAFE_INTEGER) || a.id.localeCompare(b.id),
    );
    return JSON.stringify({
      title: info.title ?? null,
      emptyValueText: info.emptyValueText ?? null,
      rows,
    });
  }

  protected abstract getProtocol(): ProtocolString;
}
