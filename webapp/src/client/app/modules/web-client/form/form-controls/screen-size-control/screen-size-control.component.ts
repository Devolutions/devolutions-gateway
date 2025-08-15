import { Component, Input, OnInit } from '@angular/core';
import { FormGroup, ReactiveFormsModule } from '@angular/forms';
import { BaseComponent } from '@shared/bases/base.component';
import { ScreenSize } from '@shared/enums/screen-size.enum';
import { WebFormService } from '@shared/services/web-form.service';
import { SelectItem } from 'primeng/api';
import { SelectModule } from 'primeng/select';
import { takeUntil } from 'rxjs/operators';

@Component({
  selector: 'web-client-screen-size-control',
  templateUrl: 'screen-size-control.component.html',
  styleUrls: ['screen-size-control.component.scss'],
  standalone: true,
  imports: [ReactiveFormsModule, SelectModule],
})
export class ScreenSizeControlComponent extends BaseComponent implements OnInit {
  @Input() parentForm: FormGroup;
  @Input() inputFormData;

  screenSizeOptions: SelectItem[];

  constructor(private formService: WebFormService) {
    super();
  }

  ngOnInit(): void {
    this.initializeFormOptions();
    this.addControlsToParentForm();
    this.setupScreenSizeChangeListener();
  }

  get showCustomSize(): boolean {
    return this.parentForm.get('screenSize').value === ScreenSize.Custom;
  }

  private setupScreenSizeChangeListener(): void {
    const screenSizeControl = this.parentForm.get('screenSize');
    if (screenSizeControl) {
      screenSizeControl.valueChanges.pipe(takeUntil(this.destroyed$)).subscribe((value) => {
        if (value === ScreenSize.Custom) {
          this.parentForm.get('customWidth').enable();
          this.parentForm.get('customHeight').enable();
        } else {
          this.parentForm.get('customWidth').disable();
          this.parentForm.get('customHeight').disable();
        }
      });
    }
  }

  private addControlsToParentForm(): void {
    if (this.parentForm) {
      this.formService.addControlToForm({
        formGroup: this.parentForm,
        controlName: 'screenSize',
        inputFormData: this.inputFormData,
        isRequired: false,
        defaultValue: ScreenSize.Default,
      });
      this.formService.addControlToForm({
        formGroup: this.parentForm,
        controlName: 'customWidth',
        inputFormData: this.inputFormData,
        isRequired: false,
        isDisabled: true,
      });
      this.formService.addControlToForm({
        formGroup: this.parentForm,
        controlName: 'customHeight',
        inputFormData: this.inputFormData,
        isRequired: false,
        isDisabled: true,
      });
    }
  }

  private initializeFormOptions(): void {
    this.formService
      .getScreenSizeOptions()
      .pipe(takeUntil(this.destroyed$))
      .subscribe({
        next: (screenSizeOptions) => {
          this.screenSizeOptions = screenSizeOptions;
        },
        error: (error) => console.error('Error fetching dropdown options', error),
      });
  }
}
