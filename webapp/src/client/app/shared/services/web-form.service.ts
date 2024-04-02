import {ChangeDetectorRef, Injectable} from "@angular/core";
import {BaseComponent} from "@shared/bases/base.component";
import {WebClientAuthMode} from "@shared/enums/web-client-auth-mode.enum";
import {Observable, of} from "rxjs";

import {SelectItem} from "primeng/api";
import {ScreenSize} from "@shared/enums/screen-size.enum";
import {WebClientProtocol} from "@shared/enums/web-client-protocol.enum";
import {FormControl, FormGroup, ValidatorFn, Validators} from "@angular/forms";

@Injectable({ providedIn: 'root' })
export class WebFormService extends BaseComponent {

  private canConnectExtraCallback: () => boolean = () => true;

  constructor() {
    super();
  }

  getAuthModeOptions(protocol:'ssh' | 'vnc'): Observable<SelectItem[]> {
    return protocol === 'vnc' ? of(WebClientAuthMode.getSelectVncItems()) : of(WebClientAuthMode.getSelectSshItems());
  }

  getProtocolOptions(): Observable<SelectItem[]> {
    return of(WebClientProtocol.getSelectItems());
  }

  getScreenSizeOptions(): Observable<SelectItem[]> {
    return of(ScreenSize.getSelectItems());
  }

  addControlToForm(
    formGroup: FormGroup,
    controlName: string,
    inputFormData?: any,
    isRequired: boolean = true,
    isDisabled: boolean = false,
    defaultValue: string | null = '',
    additionalValidator?: ValidatorFn | ValidatorFn[]
  ): void {
    if (!formGroup) return;

    const initialValue: string | number | null = inputFormData?.[controlName] ?? defaultValue;

    if (controlName in formGroup.controls) {
      isDisabled ? formGroup.controls[controlName].disable() : formGroup.controls[controlName].enable();
    } else {
      const validators: ValidatorFn[] = [];
      if (isRequired) {
        validators.push(Validators.required);
      }

      if (additionalValidator) {
        Array.isArray(additionalValidator) ? validators.push(...additionalValidator) : validators.push(additionalValidator);
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

  canConnectIfTrue(callback: () => boolean): void {
    this.canConnectExtraCallback = () => callback();
  }

  resetCanConnectCallback(){
    this.canConnectExtraCallback = () => true;
  }
}
