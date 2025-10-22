import { Component, Input, OnInit } from '@angular/core';
import { FormGroup } from '@angular/forms';
import { BaseComponent } from '@shared/bases/base.component';
import { ColorFormat } from '@shared/enums/color-format.enum';
import { SelectItemWithTooltip } from '@shared/interfaces/select-item-tooltip.interface';
import { WebFormService } from '@shared/services/web-form.service';

@Component({
  standalone: false,
  selector: 'web-client-color-format-control',
  templateUrl: 'color-format-control.component.html',
  styleUrls: ['color-format-control.component.scss'],
})
export class ColorFormatControlComponent extends BaseComponent implements OnInit {
  @Input() parentForm: FormGroup;
  @Input() inputFormData;

  colorFormatOptions: SelectItemWithTooltip[];

  constructor(private formService: WebFormService) {
    super();
  }

  ngOnInit(): void {
    this.colorFormatOptions = this.formService.getColorFormatOptions();
    this.formService.addControlToForm({
      formGroup: this.parentForm,
      controlName: 'colorFormat',
      inputFormData: this.inputFormData,
      isRequired: false,
      defaultValue: ColorFormat.Default,
    });
  }

  getSelectedTooltip(): string {
    const selectedOptionValue = this.parentForm.get('colorFormat')?.value;
    return this.colorFormatOptions.find((item) => item.value === selectedOptionValue)?.tooltipText || '';
  }
}
