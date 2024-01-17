import {
  AfterViewInit,
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
import {ScreenSize} from "@shared/enums/screen-size.enum";
import {Subject} from "rxjs";

@Component({
    selector: 'web-client-rdp-form',
    templateUrl: 'rdp-form.component.html',
    styleUrls: ['rdp-form.component.scss']
})
export class RdpFormComponent extends BaseComponent implements  OnInit,
                                                                AfterViewInit {

  @Output() isInitialized: EventEmitter<boolean> = new EventEmitter<boolean>();
  @Output() initializationMessage: EventEmitter<Error> = new EventEmitter<Error>();

  connectSessionForm: FormGroup;
  screenSizeOptions: SelectItem[];
  showMoreSettings: boolean = false;

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
    this.setupScreenSizeDropdown();
  }

  ngAfterViewInit(): void {
    this.isInitialized.emit(true);
  }

  get showCustomSize(): boolean {
    return this.connectSessionForm.get('screenSize').value === ScreenSize.Custom;
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
    console.log('newSessionTab', newSessionTab);
    this.webSessionService.addSession(newSessionTab);
  }

  initComboEnum(enums: any): SelectItem[] {
    const dropDownItems: SelectItem[] = [];
    const values: string[] = Object.keys(ScreenSize).filter(key => isNaN(Number(key)));
    for (const label of values) {
      const value = enums[label];
      dropDownItems.push({label, value});
    }
    return dropDownItems;
  }

  toggleMoreSettings(event: Event): void {
    event.preventDefault();
    this.showMoreSettings = !this.showMoreSettings;
  }

  isMoreSettingsOpened(): boolean {
    return this.showMoreSettings;
  }

  private setupScreenSizeDropdown(): void {
    this.screenSizeOptions = this.initComboEnum(ScreenSize);
    this.connectSessionForm = this.formBuilder.group({
      protocol: [0, Validators.required],
      hostname: ['', Validators.required],
      username: ['', Validators.required],
      password: ['', Validators.required],
      screenSize: [null],
      customWidth: [{value: '', disabled: true}],
      customHeight: [{value: '', disabled: true}],
      preConnectionBlob: ['']
    });

    this.subscribeToFormScreenSize();
  }

  private subscribeToFormScreenSize(): void {
    this.connectSessionForm.get('screenSize').valueChanges
      .subscribe(value => {
        if (value === ScreenSize.Custom) {
          this.connectSessionForm.get('customWidth').enable();
          this.connectSessionForm.get('customHeight').enable();
        } else {
          this.connectSessionForm.get('customWidth').disable();
          this.connectSessionForm.get('customHeight').disable();
        }
      });
  }
}
