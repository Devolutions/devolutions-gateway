import {AfterViewInit,
  Component,
  EventEmitter,
  OnInit,
  Output, Type
} from '@angular/core';
import {FormBuilder, FormGroup, Validators} from "@angular/forms";
import {SelectItem} from "primeng/api";

import {WebSessionService} from "@shared/services/web-session.service";
import {BaseComponent} from "@shared/bases/base.component";
import {WebSession} from "@shared/models/web-session.model";
import {WebClientRdpComponent} from "@gateway/modules/web-client/rdp/web-client-rdp.component";

@Component({
    selector: 'web-client-rdp-form',
    templateUrl: 'rdp-form.component.html',
    styleUrls: ['rdp-form.component.scss']
})
export class RdpFormComponent extends BaseComponent implements  OnInit,
                                                                AfterViewInit {

  @Output() isComponentViewInitialized: EventEmitter<boolean> = new EventEmitter<boolean>();

  connectSessionForm: FormGroup;

  //TODO Use proper types
  session = {
    hostname: '',
    protocol: '',
    username: '',
    password: ''
  }

  protocolSelectItems: SelectItem[] = [
    { label: 'RDP', value: '0' }
  ];

  constructor(private webSessionService: WebSessionService,
              private formBuilder: FormBuilder) {

    super();
  }

  ngOnInit(): void {
    this.connectSessionForm = this.formBuilder.group({
      protocol: [0, Validators.required],
      hostname: ['', Validators.required],
      username: ['', Validators.required],
      password: ['', Validators.required]
    });
  }

  ngAfterViewInit(): void {
    this.isComponentViewInitialized.emit(true);
  }

  onConnectSession(): void {
    const submittedData = this.connectSessionForm.value;

    const newSessionTab: WebSession<Type<WebClientRdpComponent>, any> =  new WebSession(submittedData.hostname,
                                                              WebClientRdpComponent,
                                                              submittedData,
                                                              'dvl-icon-entry-session-rdp');
    newSessionTab.name = submittedData.hostname;
    newSessionTab.component = WebClientRdpComponent;
    newSessionTab.data = submittedData;
    newSessionTab.icon = 'dvl-icon-entry-session-rdp';
    this.webSessionService.addSession(newSessionTab);
  }
}
