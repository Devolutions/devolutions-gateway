import { Injectable, OnDestroy } from '@angular/core';
import { AdUi, AdUiConfirmOptions, AdUiToastOptions } from '@devolutions/web-active-directory-gui';
import { ConfirmationService, MessageService } from 'primeng/api';
import { ActiveDirectoryTranslatorService } from './active-directory-translator.service';

const AD_CONFIRM_KEY = 'adc-confirm-dialog';
const AD_TOAST_KEY = 'adc-toast';
let nextOverlayId = 0;

@Injectable()
export class ActiveDirectoryUiService implements AdUi, OnDestroy {
  private static globalLoadingCount = 0;
  private static previousCursor: string | null = null;

  private readonly fallbackOverlayId = ++nextOverlayId;
  private loadingCount = 0;

  confirmKey = `${AD_CONFIRM_KEY}-${this.fallbackOverlayId}`;
  toastKey = `${AD_TOAST_KEY}-${this.fallbackOverlayId}`;

  constructor(
    private readonly confirmationService: ConfirmationService,
    private readonly messageService: MessageService,
    private readonly translator: ActiveDirectoryTranslatorService,
  ) {}

  setOverlayKeySuffix(suffix: string): void {
    this.confirmKey = `${AD_CONFIRM_KEY}-${suffix}`;
    this.toastKey = `${AD_TOAST_KEY}-${suffix}`;
  }

  toast(input: AdUiToastOptions): void {
    this.messageService.add({
      key: this.resolveToastKey(input.key),
      severity: input.severity,
      summary: input.summary,
      detail: input.detail,
      life: input.life ?? 5000,
      sticky: input.sticky,
    });
  }

  clearToast(key?: string): void {
    if (key) {
      this.messageService.clear(this.resolveToastKey(key));
    }
  }

  confirm(input: AdUiConfirmOptions): void {
    this.confirmationService.confirm({
      key: this.resolveConfirmKey(input.key),
      header: this.translator.translate('lblConfirm'),
      message: input.message,
      acceptLabel: input.acceptLabel ?? this.translator.translate('lblYes'),
      rejectLabel: input.rejectLabel ?? this.translator.translate('lblNo'),
      acceptButtonStyleClass: 'p-button-sm',
      rejectButtonStyleClass: 'p-button-sm p-button-text',
      accept: input.accept,
      reject: () => input.reject?.(),
    });
  }

  private resolveConfirmKey(key?: string): string {
    return !key || key === AD_CONFIRM_KEY ? this.confirmKey : key;
  }

  private resolveToastKey(key?: string): string {
    return !key || key === AD_TOAST_KEY ? this.toastKey : key;
  }

  showLoading(): void {
    if (ActiveDirectoryUiService.globalLoadingCount === 0) {
      ActiveDirectoryUiService.previousCursor = document.body.style.cursor;
    }

    this.loadingCount++;
    ActiveDirectoryUiService.globalLoadingCount++;
    document.body.style.cursor = 'wait';
  }

  hideLoading(): void {
    this.releaseLoading();
  }

  ngOnDestroy(): void {
    while (this.loadingCount > 0) {
      this.releaseLoading();
    }
  }

  private releaseLoading(): void {
    if (this.loadingCount === 0) {
      return;
    }

    this.loadingCount--;
    ActiveDirectoryUiService.globalLoadingCount = Math.max(0, ActiveDirectoryUiService.globalLoadingCount - 1);

    if (ActiveDirectoryUiService.globalLoadingCount === 0) {
      document.body.style.cursor = ActiveDirectoryUiService.previousCursor ?? '';
      ActiveDirectoryUiService.previousCursor = null;
    }
  }

  warn(message: string): void {
    this.toast({
      severity: 'warn',
      summary: this.translator.translate('lblWarning'),
      detail: message,
    });
  }

  error(message?: string, detail?: string): void {
    this.toast({
      severity: 'error',
      summary: message ?? this.translator.translate('error'),
      detail,
      sticky: true,
    });
  }

  success(message?: string, detail?: string): void {
    this.toast({
      severity: 'success',
      summary: message ?? this.translator.translate('msgSuccess'),
      detail,
    });
  }
}
