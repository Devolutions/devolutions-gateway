// TODO: uncomment when adding support for iDRAC
// import { Component, Input, OnInit } from '@angular/core';
// import { FormGroup } from '@angular/forms';
// import { SelectItem } from 'primeng/api';
//
// import { BaseComponent } from '@shared/bases/base.component';
// import { WebFormService } from '@shared/services/web-form.service';
//
// @Component({
//   standalone: false,
//   selector: 'web-client-sharing-approval-mode-control',
//   templateUrl: 'sharing-approval-mode-control.component.html',
//   styleUrls: ['sharing-approval-mode-control.component.scss'],
// })
// export class SharingApprovalModeControlComponent extends BaseComponent implements OnInit {
//   @Input() parentForm: FormGroup;
//   @Input() inputFormData;
//
//   sharingApprovalModeOptions: SelectItem[];
//
//   constructor(private formService: WebFormService) {
//     super();
//   }
//
//   ngOnInit(): void {
//     this.sharingApprovalModeOptions = this.formService.getSharingApprovalModeOptions();
//       this.formService.addControlToForm({
//           formGroup: this.parentForm,
//           controlName: 'sharingApprovalMode',
//           inputFormData: this.inputFormData,
//           isRequired: false,
//           defaultValue: null,
//       });
//   }
// }
