import { Component, Input, OnChanges, OnDestroy, OnInit, SimpleChanges } from '@angular/core';
import { FormGroup } from '@angular/forms';
import { BaseComponent } from '@shared/bases/base.component';
import { ColorFormat } from '@shared/enums/color-format.enum';
import { SelectItemWithTooltip } from '@shared/interfaces/select-item-tooltip.interface';
import { WebFormService } from '@shared/services/web-form.service';

@Component({
  selector: 'web-client-color-format-control',
  templateUrl: 'color-format-control.component.html',
  styleUrls: ['color-format-control.component.scss'],
})
export class ColorFormatControlComponent extends BaseComponent implements OnInit, OnDestroy, OnChanges {
  @Input() parentForm: FormGroup;
  @Input() inputFormData;
  @Input() disabled: boolean;
  @Input() disabledTooltip: string;

  colorFormatOptions: SelectItemWithTooltip[];

  constructor(private formService: WebFormService) {
    super();
  }

  ngOnInit(): void {
    this.colorFormatOptions = this.formService.getColorFormatOptions();

    if (!this.parentForm.contains('colorFormat')) {
      this.formService.addControlToForm({
        formGroup: this.parentForm,
        controlName: 'colorFormat',
        inputFormData: this.inputFormData,
        isRequired: false,
        defaultValue: ColorFormat.Default,
      });
    } else {
      this.parentForm.get('colorFormat').enable();
    }

    if (this.disabled) {
      this.parentForm.get('colorFormat').disable();
    }
  }

  ngOnChanges(changes: SimpleChanges): void {
    const disabled = changes.disabled;
    if (disabled) {
      // First `ngOnChanges` runs before `ngOnInit`.
      if (disabled.firstChange) {
        return;
      }

      if (disabled.currentValue) {
        this.parentForm.get('colorFormat').disable();
      } else {
        this.parentForm.get('colorFormat').enable();
      }
    }
  }

  ngOnDestroy() {
    super.ngOnDestroy();
    // Disable the control to ignore it when reading the form. At the same time, the value is preserved.
    this.parentForm.get('colorFormat').disable();
  }

  getSelectedTooltip(): string {
    if (this.disabled) {
      return this.disabledTooltip;
    }

    const selectedOptionValue = this.parentForm.get('colorFormat')?.value;
    return this.colorFormatOptions.find((item) => item.value === selectedOptionValue)?.tooltipText || '';
  }
}
