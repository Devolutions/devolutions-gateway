import {
  AfterViewInit,
  Component,
  EventEmitter, Input, OnChanges,
  OnInit,
  Output, SimpleChanges, Type
} from '@angular/core';
import {FormBuilder, FormGroup, Validators} from "@angular/forms";
import {Message, SelectItem} from "primeng/api";

import {WebSessionService} from "@shared/services/web-session.service";
import {BaseComponent} from "@shared/bases/base.component";
import {WebSession} from "@shared/models/web-session.model";
import {WebClientRdpComponent} from "@gateway/modules/web-client/rdp/web-client-rdp.component";
import {ScreenSize} from "@shared/enums/screen-size.enum";
import {ComponentStatus} from "@shared/models/component-status.model";

@Component({
    selector: 'web-client-rdp-form',
    templateUrl: 'rdp-form.component.html',
    styleUrls: ['rdp-form.component.scss']
})
export class RdpFormComponent extends BaseComponent implements  OnInit,
                                                                AfterViewInit,
                                                                OnChanges {

  @Input() isEmbedded: boolean = false;
  @Input() inputFormData: any | undefined;
  @Input() tabIndex: number | undefined;
  @Input() error: string;
  @Output() componentStatus: EventEmitter<ComponentStatus> = new EventEmitter<ComponentStatus>();

  connectSessionForm: FormGroup;
  screenSizeOptions: SelectItem[];
  showMoreSettings: boolean = false;
  messages: Message[] = [];
  showPassword: boolean = false;

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

  private initializeStatus(): void {
    const status: ComponentStatus = {
      isInitialized: true,
      tabIndex: 0
    }
    this.componentStatus.emit(status);
  }

  private addMessages(messages: Message[]) {
    this.messages = [];
    if (messages?.length > 0) {
      messages.forEach(message => {
        this.messages.push(message);
      })
    }
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

    if (this.isEmbedded) {
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

  toggleMoreSettings(event: Event): void {
    event.preventDefault();
    this.showMoreSettings = !this.showMoreSettings;
  }

  isMoreSettingsOpened(): boolean {
    return this.showMoreSettings;
  }

  private populateForm(): void {

    if (this.isEmbedded) {
      this.connectSessionForm = this.formBuilder.group({
        protocol: [this.inputFormData.protocol, Validators.required],
        hostname: [this.inputFormData.hostname, Validators.required],
        username: [this.inputFormData.username, Validators.required],
        password: [this.inputFormData.password, Validators.required],
        screenSize: [this.inputFormData.screenSize],
        customWidth: [this.inputFormData.customWidth],
        customHeight: [this.inputFormData.customHeight],
        preConnectionBlob: [this.inputFormData.preConnectionBlob],
        kdcProxyUrl: [this.inputFormData.kdcProxyUrl]
      });
    } else {
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
    }
    this.setupScreenSizeDropdown();
  }

  toggleShowPassword(): void {
    this.showPassword = !this.showPassword;
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
