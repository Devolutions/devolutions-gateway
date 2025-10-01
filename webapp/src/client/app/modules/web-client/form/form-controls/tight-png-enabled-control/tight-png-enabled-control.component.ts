import { Component, EventEmitter, Input, OnDestroy, OnInit, Output } from '@angular/core';
import { FormGroup } from '@angular/forms';

import { BaseComponent } from '@shared/bases/base.component';
import { WebFormService } from '@shared/services/web-form.service';

@Component({
  selector: 'web-client-tight-png-enabled-control',
  templateUrl: 'tight-png-enabled-control.component.html',
  styleUrls: ['tight-png-enabled-control.component.scss'],
})
export class TightPngEnabledControlComponent extends BaseComponent implements OnInit, OnDestroy {
  @Input() parentForm: FormGroup;
  @Input() inputFormData;

  @Output() controlReady = new EventEmitter<void>();

  constructor(private formService: WebFormService) {
    super();
  }

  ngOnInit(): void {
    if (!this.parentForm.contains('pngEnabled')) {
      this.formService.addControlToForm({
        formGroup: this.parentForm,
        controlName: 'pngEnabled',
        inputFormData: this.inputFormData,
        isRequired: false,
        defaultValue: true,
      });

      this.controlReady.emit();
    } else {
      this.parentForm.get('pngEnabled').enable();
    }
  }

  ngOnDestroy() {
    super.ngOnDestroy();
    // Disable the control to ignore it when reading the form. At the same time, the value is preserved.
    this.parentForm.get('pngEnabled').disable();
  }
}
