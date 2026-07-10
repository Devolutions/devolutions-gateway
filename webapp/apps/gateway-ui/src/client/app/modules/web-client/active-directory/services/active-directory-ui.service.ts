import { Injectable } from '@angular/core';
import { AdUi, AdUiConfirmOptions, AdUiToastOptions } from '@devolutions/web-active-directory-gui';
import { ConfirmationService, MessageService } from 'primeng/api';
import { ActiveDirectoryTranslatorService } from './active-directory-translator.service';

const AD_CONFIRM_KEY = 'adc-confirm-dialog';
const AD_TOAST_KEY = 'adc-toast';

@Injectable()
export class ActiveDirectoryUiService implements AdUi {
  private loadingCount = 0;

  constructor(
    private readonly confirmationService: ConfirmationService,
    private readonly messageService: MessageService,
    private readonly translator: ActiveDirectoryTranslatorService,
  ) {}

  toast(input: AdUiToastOptions): void {
    this.messageService.add({
      key: input.key ?? AD_TOAST_KEY,
      severity: input.severity,
      summary: input.summary,
      detail: input.detail,
      life: input.life ?? 5000,
      sticky: input.sticky,
    });
  }

  clearToast(key?: string): void {
    this.messageService.clear(key);
  }

  confirm(input: AdUiConfirmOptions): void {
    this.confirmationService.confirm({
      key: input.key ?? AD_CONFIRM_KEY,
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

  showLoading(): void {
    this.loadingCount++;
    document.body.style.cursor = 'wait';
  }

  hideLoading(): void {
    this.loadingCount = Math.max(0, this.loadingCount - 1);

    if (this.loadingCount === 0) {
      document.body.style.cursor = 'default';
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
