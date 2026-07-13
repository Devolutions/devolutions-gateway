import {
  AfterViewInit,
  Component,
  ElementRef,
  EventEmitter,
  HostBinding,
  OnDestroy,
  Output,
  ViewChild,
} from '@angular/core';
import {
  ActiveDirectoryConnectionParams,
  ActiveDirectoryMainHandle,
  AD_DATA_PROVIDER,
  AD_SESSION_MANAGER,
  AD_TRANSLATOR,
  AD_UI,
  AdConnectionError,
  AdConnectionEventType,
  matchTranslateKey,
} from '@devolutions/web-active-directory-gui';
import { DVL_ACTIVE_DIRECTORY_ICON, DVL_WARNING_ICON, JET_AD_URL } from '@gateway/app.constants';
import { WebClientBaseComponent } from '@shared/bases/base-web-client.component';
import { GatewayAlertMessageService } from '@shared/components/gateway-alert-message/gateway-alert-message.service';
import { ActiveDirectoryConnectionParameters } from '@shared/interfaces/connection-params.interfaces';
import { ActiveDirectoryFormDataInput } from '@shared/interfaces/forms.interfaces';
import { ComponentStatus } from '@shared/models/component-status.model';
import { AnalyticService, ProtocolString } from '@shared/services/analytic.service';
import { UtilsService } from '@shared/services/utils.service';
import { DefaultLdapPort, DefaultLdapsPort, WebClientService } from '@shared/services/web-client.service';
import { WebSessionService } from '@shared/services/web-session.service';
import { EMPTY, from, Observable, of, Subscription } from 'rxjs';
import { catchError, map, switchMap, takeUntil } from 'rxjs/operators';
import { v4 as uuidv4 } from 'uuid';
import { ActiveDirectoryDataService } from './services/active-directory-data.service';
import { ActiveDirectorySessionManagerService } from './services/active-directory-session-manager.service';
import { ActiveDirectorySessionStoreService } from './services/active-directory-session-store.service';
import { ActiveDirectoryTranslatorService } from './services/active-directory-translator.service';
import { ActiveDirectoryUiService } from './services/active-directory-ui.service';

@Component({
  standalone: false,
  templateUrl: 'web-client-active-directory.component.html',
  styleUrls: ['web-client-active-directory.component.scss'],
  providers: [
    ActiveDirectoryDataService,
    ActiveDirectorySessionManagerService,
    ActiveDirectorySessionStoreService,
    ActiveDirectoryTranslatorService,
    ActiveDirectoryUiService,
    { provide: AD_DATA_PROVIDER, useExisting: ActiveDirectoryDataService },
    { provide: AD_SESSION_MANAGER, useExisting: ActiveDirectorySessionManagerService },
    { provide: AD_TRANSLATOR, useExisting: ActiveDirectoryTranslatorService },
    { provide: AD_UI, useExisting: ActiveDirectoryUiService },
  ],
})
export class WebClientActiveDirectoryComponent extends WebClientBaseComponent implements AfterViewInit, OnDestroy {
  @HostBinding('attr.data-ad-theme-bridge') readonly adBridge = '1';

  @Output() readonly componentStatus = new EventEmitter<ComponentStatus>();
  @Output() readonly sizeChange = new EventEmitter<void>();

  @ViewChild('activeDirectoryContainer') activeDirectoryContainerRef: ElementRef<HTMLElement>;

  formData: ActiveDirectoryFormDataInput;
  renderActiveDirectory = false;

  private activeDirectoryHandle: ActiveDirectoryMainHandle | null = null;
  private activeDirectoryEventsSubscription: Subscription | null = null;
  private renderActiveDirectoryTimeout: ReturnType<typeof setTimeout> | null = null;
  private activeDirectoryForwardingSessionId: string | null = null;

  constructor(
    protected gatewayAlertMessageService: GatewayAlertMessageService,
    protected analyticService: AnalyticService,
    private readonly utils: UtilsService,
    private readonly webClientService: WebClientService,
    private readonly webSessionService: WebSessionService,
    private readonly activeDirectoryDataService: ActiveDirectoryDataService,
    private readonly activeDirectorySessionManager: ActiveDirectorySessionManagerService,
    private readonly activeDirectoryTranslator: ActiveDirectoryTranslatorService,
    private readonly activeDirectoryUiService: ActiveDirectoryUiService,
  ) {
    super(gatewayAlertMessageService, analyticService);
  }

  ngAfterViewInit(): void {
    this.activeDirectoryUiService.setOverlayKeySuffix(this.webSessionId);

    this.renderActiveDirectoryTimeout = setTimeout(() => {
      this.renderActiveDirectory = true;
      this.renderActiveDirectoryTimeout = null;
    });
  }

  override ngOnDestroy(): void {
    if (this.renderActiveDirectoryTimeout) {
      clearTimeout(this.renderActiveDirectoryTimeout);
      this.renderActiveDirectoryTimeout = null;
    }

    this.activeDirectoryEventsSubscription?.unsubscribe();

    if (this.activeDirectoryHandle && !this.currentStatus.isDisabled) {
      const wasInitialized = this.currentStatus.isInitialized;
      this.closeActiveDirectoryHandle();

      if (wasInitialized) {
        this.currentStatus.isInitialized = false;
        this.webClientConnectionClosed();
      }
    }

    if (this.activeDirectoryForwardingSessionId) {
      this.activeDirectorySessionManager.clearWebSessionConfig(this.activeDirectoryForwardingSessionId);
      this.activeDirectoryForwardingSessionId = null;
    }

    super.ngOnDestroy();
  }

  private closeActiveDirectoryHandle(): void {
    if (this.activeDirectoryHandle) {
      this.activeDirectoryHandle.close();
      this.activeDirectoryHandle = null;
    }
  }

  get confirmDialogKey(): string {
    return this.activeDirectoryUiService.confirmKey;
  }

  get toastKey(): string {
    return this.activeDirectoryUiService.toastKey;
  }

  onMainReady(handle: ActiveDirectoryMainHandle): void {
    this.activeDirectoryHandle = handle;
    this.subscribeToActiveDirectoryEvents(handle);
    this.startConnectionProcess();
  }

  startTerminationProcess(): void {
    this.currentStatus.isDisabledByUser = true;
    this.sendTerminateSessionCmd();
    this.disableComponentStatus();
    this.webClientConnectionClosed();
  }

  sendTerminateSessionCmd(): void {
    if (!this.activeDirectoryHandle) {
      return;
    }

    this.currentStatus.isInitialized = false;

    this.closeActiveDirectoryHandle();
  }

  private startConnectionProcess(): void {
    this.getFormData()
      .pipe(
        takeUntil(this.destroyed$),
        switchMap(() => this.fetchParameters(this.formData)),
        switchMap((params) => this.webClientService.fetchActiveDirectoryToken(params)),
        switchMap((params) => from(this.activeDirectoryDataService.initializeWasm()).pipe(map(() => params))),
        map((params) => this.toActiveDirectoryConnectionParams(params)),
        switchMap((params) => this.callConnect(params)),
        catchError((error) => {
          this.handleSessionError(this.toAdConnectionError(error), true);
          return EMPTY;
        }),
      )
      .subscribe();
  }

  private callConnect(connectionParameters: ActiveDirectoryConnectionParams): Observable<void> {
    if (!this.activeDirectoryHandle) {
      return EMPTY;
    }

    this.loading = true;
    return this.activeDirectoryHandle.connect(connectionParameters);
  }

  private getFormData(): Observable<void> {
    return from(this.webSessionService.getWebSession(this.webSessionId)).pipe(
      map((currentWebSession) => {
        this.formData = currentWebSession.data as ActiveDirectoryFormDataInput;
        this.sessionInfoUsername = this.formData.username;
        this.refreshSessionInfo();
      }),
    );
  }

  private fetchParameters(formData: ActiveDirectoryFormDataInput): Observable<ActiveDirectoryConnectionParameters> {
    const sessionId = uuidv4();
    this.activeDirectoryForwardingSessionId = sessionId;
    const defaultPort = formData.useLdaps ? DefaultLdapsPort : DefaultLdapPort;
    const extractedData = this.utils.string.extractHostnameAndPort(
      formData.hostname,
      Number(formData.port) || defaultPort,
    );
    const gatewayAddress = new URL(JET_AD_URL, window.location.href).href;

    this.sessionInfoUrl = this.toUserFacingUrl(gatewayAddress);
    this.sessionInfoUsername = formData.username;
    this.refreshSessionInfo();

    return of({
      host: extractedData.hostname,
      port: extractedData.port,
      username: formData.username,
      password: formData.password,
      domain: formData.domain ?? '',
      gatewayAddress,
      sessionId,
      useLdaps: formData.useLdaps,
      organizationalUnit: formData.organizationalUnit,
    });
  }

  private toActiveDirectoryConnectionParams(
    connectionParameters: ActiveDirectoryConnectionParameters,
  ): ActiveDirectoryConnectionParams {
    this.activeDirectorySessionManager.setWebSessionConfig({
      sessionId: connectionParameters.sessionId,
      // Gateway standalone does not expose a DVLS gateway identifier here.
      gatewayId: '',
      hostname: connectionParameters.host,
      port: connectionParameters.port,
      username: connectionParameters.username,
      password: connectionParameters.password,
      domain: connectionParameters.domain,
      useSSL: connectionParameters.useLdaps,
      token: connectionParameters.token,
      kdcProxyUrl: connectionParameters.kdcUrl,
      getGatewayWebSocketUrl: (path: string) => new URL(path, window.location.href).href,
    });

    return {
      connectionSettings: {
        host: connectionParameters.host,
        port: connectionParameters.port.toString(),
        username: connectionParameters.username,
        password: connectionParameters.password,
        domain: connectionParameters.domain ?? '',
        gatewayUrl: connectionParameters.gatewayAddress,
        token: connectionParameters.token,
        kdcUrl: connectionParameters.kdcUrl,
      },
      isLdaps: connectionParameters.useLdaps,
      sessionId: connectionParameters.sessionId,
      sessionRecordingTokens: {
        gatewayId: null,
        recordingUrl: null,
        shouldStartRecording: 'no',
      },
    };
  }

  private subscribeToActiveDirectoryEvents(handle: ActiveDirectoryMainHandle): void {
    this.activeDirectoryEventsSubscription?.unsubscribe();
    this.activeDirectoryEventsSubscription = handle.adConnectionEvents
      .pipe(takeUntil(this.destroyed$))
      .subscribe((event) => {
        switch (event.type) {
          case AdConnectionEventType.Connected:
            this.handleSessionStarted();
            break;
          case AdConnectionEventType.Terminated:
            this.handleSessionTerminated(this.activeDirectoryTranslator.translate('msgSessionTerminated'));
            break;
          case AdConnectionEventType.Error:
            this.handleSessionError(event.error, !this.currentStatus.isInitialized);
            break;
          case AdConnectionEventType.Warning:
            this.activeDirectoryUiService.warn(this.activeDirectoryTranslator.translate(event.message));
            break;
          case AdConnectionEventType.Success:
            this.activeDirectoryUiService.success(this.activeDirectoryTranslator.translate(event.message));
            break;
        }
      });
  }

  private handleSessionStarted(): void {
    this.loading = false;
    void this.webSessionService.updateWebSessionIcon(this.webSessionId, DVL_ACTIVE_DIRECTORY_ICON);
    this.initializeStatus();
    this.handleConnectionSuccess();
  }

  private handleSessionTerminated(message: string): void {
    this.loading = false;

    if (this.currentStatus.isDisabledByUser) {
      return;
    }

    this.currentStatus.terminationMessage = {
      summary: message,
      severity: 'error',
    };
    void this.webSessionService.updateWebSessionIcon(this.webSessionId, DVL_WARNING_ICON);
    this.disableComponentStatus();
    this.webClientConnectionClosed();
  }

  private handleSessionError(error: AdConnectionError, disableComponent = true): void {
    this.loading = false;
    const summary = this.getErrorSummary(error);
    const detail = this.getErrorDetail(error, summary);

    this.activeDirectoryUiService.error(summary, detail);
    console.error(detail);

    if (!disableComponent) {
      return;
    }

    this.currentStatus.terminationMessage = {
      summary,
      detail,
      severity: 'error',
    };

    void this.webSessionService.updateWebSessionIcon(this.webSessionId, DVL_WARNING_ICON);
    this.disableComponentStatus();
    this.webClientConnectionClosed();
  }

  private getErrorSummary(error: AdConnectionError): string {
    const causeTranslationKey = this.getErrorTranslationKeyFromCause(error.cause);
    if (causeTranslationKey) {
      return this.activeDirectoryTranslator.translate(causeTranslationKey);
    }

    if (error.code === 'other') {
      return this.activeDirectoryTranslator.translate('AnUnexpectedErrorOccured');
    }

    return this.activeDirectoryTranslator.translate(matchTranslateKey(error.code));
  }

  private getErrorDetail(error: AdConnectionError, summary: string): string | undefined {
    const causeMessage = typeof error.cause === 'string' ? error.cause : undefined;
    const translatedMessage = this.activeDirectoryTranslator.translate(error.message);

    if (causeMessage && causeMessage !== translatedMessage) {
      return causeMessage;
    }

    return translatedMessage && translatedMessage !== summary ? translatedMessage : undefined;
  }

  private getErrorTranslationKeyFromCause(cause: unknown): string | undefined {
    if (typeof cause !== 'string') {
      return undefined;
    }

    const normalizedCause = cause.toLowerCase();

    if (
      normalizedCause.includes('entry_exists') ||
      normalizedCause.includes('entryalreadyexists') ||
      normalizedCause.includes('entry already exists') ||
      normalizedCause.includes('problem 6005')
    ) {
      return 'AlreadyExists';
    }

    return undefined;
  }

  private initializeStatus(): void {
    this.currentStatus = {
      id: this.webSessionId,
      isInitialized: true,
      isDisabled: false,
      isDisabledByUser: false,
    };
  }

  private handleConnectionSuccess(): void {
    this.hideSpinnerOnly = true;
    this.activeDirectoryUiService.success(this.activeDirectoryTranslator.translate('msgConnected'));
    this.analyticHandle = this.analyticService.sendOpenEvent(this.getProtocol());
  }

  private disableComponentStatus(): void {
    if (this.currentStatus.isDisabled) {
      return;
    }

    this.currentStatus.id ??= this.webSessionId;
    this.currentStatus.isDisabled = true;
    this.componentStatus.emit(this.currentStatus);
  }

  private toAdConnectionError(error: unknown): AdConnectionError {
    if (this.isAdConnectionError(error)) {
      return error;
    }

    return {
      code: 'other',
      message: error instanceof Error ? error.message : `${error}`,
      cause: error,
    };
  }

  private isAdConnectionError(error: unknown): error is AdConnectionError {
    return (
      typeof error === 'object' &&
      error !== null &&
      'code' in error &&
      'message' in error &&
      typeof (error as AdConnectionError).message === 'string'
    );
  }

  protected getProtocol(): ProtocolString {
    return 'ActiveDirectory';
  }
}
