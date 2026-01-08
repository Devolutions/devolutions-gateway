// TODO: uncomment when adding support for VMWare
// import { Component, Input, OnInit } from '@angular/core';
// import { FormGroup } from '@angular/forms';
//
// import { BaseComponent } from '@shared/bases/base.component';
// import { WebFormService } from '@shared/services/web-form.service';
//
// @Component({
//   standalone: false,
//   selector: 'web-client-force-ws-port-control',
//   templateUrl: 'force-ws-port-control.component.html',
//   styleUrls: ['force-ws-port-control.component.scss'],
// })
// export class ForceWsPortControlComponent extends BaseComponent implements OnInit {
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
//       controlName: 'forceWsPort',
//       inputFormData: this.inputFormData,
//       isRequired: false,
//       defaultValue: false,
//     });
//   }
// }
