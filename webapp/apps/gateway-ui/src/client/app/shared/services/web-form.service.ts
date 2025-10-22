import { ChangeDetectorRef, Injectable } from '@angular/core';
import { FormControl, FormGroup, ValidatorFn, Validators } from '@angular/forms';
import { BaseComponent } from '@shared/bases/base.component';
import { ColorFormat } from '@shared/enums/color-format.enum';
import { ScreenSize } from '@shared/enums/screen-size.enum';
import { WebClientAuthMode } from '@shared/enums/web-client-auth-mode.enum';
import { WebClientProtocol } from '@shared/enums/web-client-protocol.enum';
import { SelectItemWithTooltip } from '@shared/interfaces/select-item-tooltip.interface';
import { SelectItem } from 'primeng/api';
import { Observable, of } from 'rxjs';
import { ArdQualityMode } from '../enums/ard-quality-mode.enum';
import { Encoding } from '../enums/encoding.enum';
import { ResolutionQuality } from '../enums/resolution-quality.enum';
import { ExtraSessionParameter } from './web-session.service';

@Injectable({ providedIn: 'root' })
export class WebFormService extends BaseComponent {
  private canConnectExtraCallback: () => boolean = () => true;

  private extraSessionParameter: ExtraSessionParameter = {};

  constructor() {
    super();
  }

  getAuthModeOptions(protocol: 'ssh' | 'vnc'): Observable<SelectItem[]> {
    return protocol === 'vnc' ? of(WebClientAuthMode.getSelectVncItems()) : of(WebClientAuthMode.getSelectSshItems());
  }

  getProtocolOptions(): Observable<SelectItem[]> {
    return of(WebClientProtocol.getSelectItems());
  }

  getScreenSizeOptions(): Observable<SelectItem[]> {
    return of(ScreenSize.getSelectItems());
  }

  // TODO: uncomment when adding support for iDRAC
  // getSharingApprovalModeOptions(): SelectItem[] {
  //   return SharingApprovalMode.getSelectItems();
  // }

  getResolutionQualityOptions(): SelectItem[] {
    return ResolutionQuality.getSelectItems();
  }

  getArdQualityModeOptions(): SelectItem[] {
    return ArdQualityMode.getSelectItems();
  }

  getColorFormatOptions(): SelectItemWithTooltip[] {
    return ColorFormat.getSelectItems();
  }

  getSupportedEncodings(): SelectItem[] {
    return Encoding.getSelectItems();
  }

  setExtraSessionParameter(extraSessionParameter: ExtraSessionParameter): void {
    this.extraSessionParameter = extraSessionParameter;
  }

  getExtraSessionParameter(): ExtraSessionParameter {
    return this.extraSessionParameter;
  }

  addControlToForm(options: {
    formGroup: FormGroup;
    controlName: string;
    inputFormData?: unknown;
    isRequired?: boolean;
    isDisabled?: boolean;
    defaultValue?: string | string[] | number | boolean | null;
    additionalValidator?: ValidatorFn | ValidatorFn[];
  }): void {
    const {
      formGroup,
      controlName,
      inputFormData,
      isRequired = true,
      isDisabled = false,
      defaultValue = '',
      additionalValidator,
    } = options;

    if (!formGroup) return;

    let initialValue: string | string[] | number | boolean | null = inputFormData?.[controlName] ?? defaultValue;

    if (typeof defaultValue === 'boolean' && typeof initialValue === 'string') {
      initialValue = initialValue === 'true';
    }

    if (controlName in formGroup.controls) {
      isDisabled ? formGroup.controls[controlName].disable() : formGroup.controls[controlName].enable();
    } else {
      const validators: ValidatorFn[] = [];
      if (isRequired) {
        validators.push(Validators.required);
      }

      if (additionalValidator) {
        Array.isArray(additionalValidator)
          ? validators.push(...additionalValidator)
          : validators.push(additionalValidator);
      }

      formGroup.addControl(controlName, new FormControl({ value: initialValue, disabled: isDisabled }, validators));
    }
  }

  /*
   * This function should be used sparingly in cases to avoid:
   * "ExpressionChangedAfterItHasBeenCheckedError"
   *
   * It manually triggers change detection to ensure view is updated after dynamic form control updates.
   * (in general Angular takes care of this, but...)
   *
   * It addresses the "ExpressionChangedAfterItHasBeenCheckedError" by ensuring changes to form validity
   * & control states are updated to the view immediately after asynchronous operations
   *
   * Examples: when Protocol selection changes or when authMode selection changes
   *
   * KAH March 21, 2024
   */
  detectFormChanges(cdr: ChangeDetectorRef): void {
    cdr.detectChanges();
  }

  public canConnect(form: FormGroup): boolean {
    return form.valid && this.canConnectExtraCallback();
  }

  canConnectIfAlsoTrue(callback: () => boolean): void {
    this.canConnectExtraCallback = () => callback();
  }

  resetCanConnectCallback() {
    this.canConnectExtraCallback = () => true;
  }
}
