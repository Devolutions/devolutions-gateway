import { Component, Input, OnInit } from '@angular/core';
import { FormGroup } from '@angular/forms';
import { ArdFormDataInput } from '@gateway/shared/interfaces/forms.interfaces';

import { BaseComponent } from '@shared/bases/base.component';

@Component({
  selector: 'ard-form',
  templateUrl: 'ard-form.component.html',
  styleUrls: ['ard-form.component.scss'],
})
export class ArdFormComponent extends BaseComponent implements OnInit {
  @Input() form: FormGroup;
  @Input() inputFormData: ArdFormDataInput;

  showMoreSettings = false;

  constructor() {
    super();
  }

  ngOnInit(): void {}

  toggleMoreSettings(event: Event): void {
    event.preventDefault();
    this.showMoreSettings = !this.showMoreSettings;
  }
}
