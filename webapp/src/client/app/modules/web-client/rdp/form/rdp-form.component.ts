import {
  AfterViewInit,
  Component,
  EventEmitter, Input, OnChanges,
  OnInit,
  Output, SimpleChanges, Type
} from '@angular/core';
import {FormBuilder, FormControl, FormGroup, Validators} from "@angular/forms";
import {Message, SelectItem} from "primeng/api";

import {WebSessionService} from "@shared/services/web-session.service";
import {BaseComponent} from "@shared/bases/base.component";
import {WebSession} from "@shared/models/web-session.model";
import {WebClientRdpComponent} from "@gateway/modules/web-client/rdp/web-client-rdp.component";
import {ScreenSize} from "@shared/enums/screen-size.enum";
import {ComponentStatus} from "@shared/models/component-status.model";

interface AutoCompleteInput {
  hostname: string;
}

@Component({
    selector: 'web-client-rdp-form',
    templateUrl: 'rdp-form.component.html',
    styleUrls: ['rdp-form.component.scss']
})
export class RdpFormComponent extends BaseComponent implements  OnInit,
                                                                AfterViewInit,
                                                                OnChanges {

  @Input() isFormExists: boolean = false;
  @Input() inputFormData: any | undefined;
  @Input() tabIndex: number | undefined;
  @Input() error: string;

  @Output() componentStatus: EventEmitter<ComponentStatus> = new EventEmitter<ComponentStatus>();

  connectSessionForm: FormGroup;
  screenSizeOptions: SelectItem[];
  showMoreSettings: boolean = false;
  messages: Message[] = [];
  showPassword: boolean = false;

  hostnames!: any[]
  filteredHostnames!: any[];

  protocolSelectItems: SelectItem[] = [
    { label: 'RDP', value: '0' }
  ];

  constructor(private webSessionService: WebSessionService,
              private formBuilder: FormBuilder) {

    super();
  }

  ngOnInit(): void {
    this.populateForm()
  }

  ngAfterViewInit(): void {
    this.initializeStatus();
  }

  ngOnChanges(changes: SimpleChanges): void {
    this.messages = [];

    if (changes.error && this.error) {
      let message: string = this.error;

      if (changes.error && this.error) {
        setTimeout(() => {
          this.addMessages([{
            severity: 'error',
            summary: 'Error', //For translation lblError
            detail: message
          }]);
        }, 500);
      }
    }
  }

  get showCustomSize(): boolean {
    return this.connectSessionForm.get('screenSize').value === ScreenSize.Custom;
  }

  onConnectSession(): void {
    const submittedData = this.connectSessionForm.value;
    submittedData.hostname = this.processHostname(submittedData.autoComplete);

    const newSessionTab: WebSession<Type<WebClientRdpComponent>, any> =  new WebSession(submittedData.hostname,
                                                              WebClientRdpComponent,
                                                              submittedData,
                                                              WebClientRdpComponent.DVL_RDP_ICON);
    newSessionTab.name = submittedData.hostname;
    newSessionTab.component = WebClientRdpComponent;
    newSessionTab.data = submittedData;

    if (this.isFormExists) {
      this.webSessionService.updateSession(this.tabIndex, newSessionTab);
    } else {
      this.webSessionService.addSession(newSessionTab);
    }
  }

  initComboEnum(enums: any): SelectItem[] {
    const dropDownItems: SelectItem[] = [];
    const values: string[] = Object.keys(ScreenSize).filter(key => isNaN(Number(key)));
    for (const label of values) {
      const noLetterRLabel: string = label.startsWith('R') ? label.substring(1) : label;
      const value = enums[label];
      dropDownItems.push({label:noLetterRLabel, value});
    }
    return dropDownItems;
  }

  toggleShowPassword(): void {
    this.showPassword = !this.showPassword;
  }

  toggleMoreSettings(event: Event): void {
    event.preventDefault();
    this.showMoreSettings = !this.showMoreSettings;
  }

  isMoreSettingsOpened(): boolean {
    return this.showMoreSettings;
  }

  isHostnamesExists(): boolean {
    return this.hostnames.length > 0;
  }

  filterHostname(event: any): void {
    const query = event.query.toLowerCase();

    this.filteredHostnames = this.hostnames.filter(hostnameObj =>
      hostnameObj.hostname.toLowerCase().startsWith(query)
    );
  }

  private isHostnameInArray(hostname: string, array: AutoCompleteInput[]): boolean {
    return array.some(obj => obj.hostname === hostname);
  }

  private processHostname(autoCompleteInput: any): string {
    this.addHostnameToLocalStorage(autoCompleteInput);

    if (typeof autoCompleteInput === 'string') {
      return autoCompleteInput;
    }

    return autoCompleteInput?.hostname || '';
  }

  private processAutoCompleteInput(input: string | AutoCompleteInput): AutoCompleteInput {
    return typeof input === 'string' ? {'hostname': input} : input;
  }

  private addHostnameToLocalStorage(hostname: string | AutoCompleteInput): void {
    try {
      const hostnameObj: AutoCompleteInput = this.processAutoCompleteInput(hostname);

      let hostnames = JSON.parse(localStorage.getItem('hostnames') || '[]');
      if (!this.isHostnameInArray(hostnameObj.hostname, hostnames)) {
        hostnames.push(hostnameObj);
        localStorage.setItem('hostnames', JSON.stringify(hostnames));

        this.populateAutoComplete();
      }
    } catch (e) {
      console.error(e);
    }
  }

  private initializeStatus(): void {
    const status: ComponentStatus = {
      isInitialized: true,
      tabIndex: 0
    }
    this.componentStatus.emit(status);
  }

  private addMessages(messages: Message[]): void {
    this.messages = [];
    if (messages?.length > 0) {
      messages.forEach(message => {
        this.messages.push(message);
      })
    }
  }

  private populateForm(): void {
    this.populateAutoComplete();

    if (this.isFormExists) {
      this.connectSessionForm = this.formBuilder.group({
        protocol: [this.inputFormData.protocol, Validators.required],
        autoComplete: new FormControl('', Validators.required),
        hostname: [''],
        username: [this.inputFormData.username, Validators.required],
        password: [this.inputFormData.password, Validators.required],
        screenSize: [this.inputFormData.screenSize],
        customWidth: [this.inputFormData.customWidth],
        customHeight: [this.inputFormData.customHeight],
        kdcProxyUrl: [this.inputFormData.kdcProxyUrl],
        preConnectionBlob: [this.inputFormData.preConnectionBlob]
      });
    } else {
      this.connectSessionForm = this.formBuilder.group({
        protocol: [0, Validators.required],
        autoComplete: new FormControl('', Validators.required),
        hostname: [''],
        username: ['', Validators.required],
        password: ['', Validators.required],
        screenSize: [null],
        customWidth: [{value: '', disabled: true}],
        customHeight: [{value: '', disabled: true}],
        kdcProxyUrl: [''],
        preConnectionBlob: ['']
      });
    }
    this.setupScreenSizeDropdown();
  }

  private populateAutoComplete(): void {
    //localStorage.clear();
    this.hostnames = JSON.parse(localStorage.getItem('hostnames') || '[]');
  }

  private setupScreenSizeDropdown(): void {
    //TODO take into account the form data if embedded
    this.screenSizeOptions = this.initComboEnum(ScreenSize);
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
