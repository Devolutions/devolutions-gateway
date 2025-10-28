// TODO: uncomment when adding support for iDRAC
// import { Component, Input, OnInit } from '@angular/core';
// import { FormGroup } from '@angular/forms';
//
// import { BaseComponent } from '@shared/bases/base.component';
// import { WebFormService } from '@shared/services/web-form.service';
//
// @Component({
//   selector: 'web-client-request-shared-session-control',
//   templateUrl: 'request-shared-session-control.component.html',
//   styleUrls: ['request-shared-session-control.component.scss'],
// })
// export class RequestSharedSessionControlComponent extends BaseComponent implements OnInit {
//   @Input() parentForm: FormGroup;
//   @Input() inputFormData;
//
//   constructor(private formService: WebFormService) {
//     super();
//   }
//
//   ngOnInit(): void {
//     this.formService.addControlToForm({
//       formGroup: this.parentForm,
//       controlName: 'requestSharedSession',
//       inputFormData: this.inputFormData,
//       isRequired: false,
//       defaultValue: false,
//     });
//   }
// }
