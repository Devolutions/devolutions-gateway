import {
  Component,
  EventEmitter, Input, OnChanges,
  OnInit,
  Output, SimpleChanges, Type
} from '@angular/core';
import {AbstractControl, FormBuilder, FormControl, FormGroup, ValidatorFn, Validators} from "@angular/forms";
import {Message, SelectItem} from "primeng/api";

import {WebSessionService} from "@shared/services/web-session.service";
import {BaseComponent} from "@shared/bases/base.component";
import {WebSession} from "@shared/models/web-session.model";
import {WebClientRdpComponent} from "@gateway/modules/web-client/rdp/web-client-rdp.component";
import {ScreenSize} from "@shared/enums/screen-size.enum";
import {ComponentStatus} from "@shared/models/component-status.model";
import {
  HostnameObject,
  RdpFormDataInput,
  AutoCompleteInput,
  PROTOCOL_SELECT_ITEMS
} from "@shared/services/web-client.service";
import {EMPTY, Observable, of} from "rxjs";
import {catchError, map, switchMap, takeUntil} from "rxjs/operators";
import {StorageService} from "@shared/services/utils/storage.service";

@Component({
    selector: 'web-client-rdp-form',
    templateUrl: 'rdp-form.component.html',
    styleUrls: ['rdp-form.component.scss']
})
export class RdpFormComponent extends BaseComponent implements  OnInit,
                                                                OnChanges {

  @Input() isFormExists: boolean = false;
  @Input() webSessionId: string | undefined;
  @Input() inputFormData: RdpFormDataInput | undefined;
  @Input() error: string;

  @Output() componentStatus: EventEmitter<ComponentStatus> = new EventEmitter<ComponentStatus>();
  @Output() sizeChange: EventEmitter<void> = new EventEmitter<void>();

  connectSessionForm: FormGroup;
  screenSizeOptions: SelectItem[];
  showMoreSettings: boolean = false;
  messages: Message[] = [];
  showPassword: boolean = false;

  hostnames!: HostnameObject[];
  filteredHostnames!: HostnameObject[];

  protocolSelectItems: SelectItem[];

  constructor(private webSessionService: WebSessionService,
              private storageService: StorageService,
              private formBuilder: FormBuilder) {
    super();
    this.protocolSelectItems = PROTOCOL_SELECT_ITEMS;
  }

  ngOnInit(): void {
    this.populateForm()
  }

  ngOnChanges(changes: SimpleChanges): void {
    this.messages = [];

    if (changes.error && this.error) {
      let message: string = this.error;

      setTimeout(() => {
        this.addMessages([{
          severity: 'error',
          summary: 'Error', //For translation lblError
          detail: message
        }]);
      }, 500);
    }
  }

  get showCustomSize(): boolean {
    return this.connectSessionForm.get('screenSize').value === ScreenSize.Custom;
  }

  onConnectSession(): void {

    const submittedData: RdpFormDataInput = this.connectSessionForm.value;
    this.manageScreenSize(submittedData.screenSize);

    submittedData.hostname = this.processHostname(submittedData.autoComplete);

    const webSession: WebSession<Type<WebClientRdpComponent>, RdpFormDataInput> =  new WebSession(submittedData.hostname,
                                                              WebClientRdpComponent,
                                                              submittedData,
                                                              WebClientRdpComponent.DVL_RDP_ICON);
    webSession.name = submittedData.hostname;
    webSession.component = WebClientRdpComponent;
    webSession.data = submittedData;

    if (this.isFormExists) {
      webSession.id = this.webSessionId;
      this.webSessionService.updateSession(webSession);
    } else {
      this.webSessionService.addSession(webSession);
    }
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

  kdcServerUrlValidator(): ValidatorFn {
    return (control: AbstractControl): { [key: string]: any } | null => {
      if (!control.value) {
        return null;
      }

      const validTcpProtocol: boolean = /^(tcp|udp):\/\/.*$/.test(control.value);
      return validTcpProtocol ? null : { 'invalidKdcProtocol': { value: control.value } };
    };
  }

  private manageScreenSize(formScreenSize): void {
    if (formScreenSize === ScreenSize.FullScreen) {
      const width: number = window.screen.width;
      const height: number = window.screen.height;
      this.webSessionService.setWebSessionScreenSize({ width, height });
    } else {
      this.sizeChange.emit();
    }
  }

  private isHostnameInArray(hostname: string, array: AutoCompleteInput[]): boolean {
    return array.some(obj => obj.hostname === hostname);
  }

  private processHostname(autoCompleteInput: AutoCompleteInput): string {
    this.addHostnameToStorage(autoCompleteInput);

    if (typeof autoCompleteInput === 'string') {
      return autoCompleteInput;
    }

    return autoCompleteInput?.hostname || '';
  }

  private processAutoCompleteInput(input: string | AutoCompleteInput): AutoCompleteInput {
    return typeof input === 'string' ? {'hostname': input} : input;
  }

  private addHostnameToStorage(hostname: string | AutoCompleteInput): void {
    try {
      const hostnameObj: AutoCompleteInput = this.processAutoCompleteInput(hostname);
      const hostnames: AutoCompleteInput[] | null = this.storageService.getItem<AutoCompleteInput[]>('hostnames');

      if (!this.isHostnameInArray(hostnameObj.hostname, hostnames)) {
        hostnames.push(hostnameObj);

        this.storageService.setItem('hostnames', hostnames);

        this.populateAutoCompleteLists();
      }
    } catch (e) {
      console.error(e);
    }
  }

  private addMessages(newMessages: Message[]): void {

    const areThereNewMessages: boolean = newMessages.some(newMsg =>
      !this.messages.some(existingMsg => existingMsg.summary === newMsg.summary &&
                                                  existingMsg.detail === newMsg.detail));

    if (areThereNewMessages) {
      this.messages = [...this.messages, ...newMessages];
    }
  }

  private buildForm(): Observable<FormGroup> {
    const formControls = {
      protocol: [0, Validators.required],
      autoComplete: new FormControl('', Validators.required),
      hostname: [''],
      username: ['', Validators.required],
      password: ['', Validators.required],
      screenSize: [null],
      customWidth: [{value: '', disabled: true}],
      customHeight: [{value: '', disabled: true}],
      kdcUrl: ['', [this.kdcServerUrlValidator()]],
      preConnectionBlob: ['']
    };

    if (this.isFormExists && this.inputFormData) {
      return of(
        this.formBuilder.group({
          ...formControls,
          autoComplete: new FormControl('', Validators.required),
          hostname: [''],
          protocol: [this.inputFormData.protocol, Validators.required],
          username: [this.inputFormData.username, Validators.required],
          password: [this.inputFormData.password, Validators.required],
          screenSize: [this.inputFormData.screenSize],
          customWidth: [this.inputFormData.customWidth],
          customHeight: [this.inputFormData.customHeight],
          kdcUrl: [this.inputFormData.kdcUrl, [this.kdcServerUrlValidator()]],
          preConnectionBlob: [this.inputFormData.preConnectionBlob]
        })
      );

    } else {
      return of(this.formBuilder.group(formControls));
    }
  }

  private populateForm(): void {
    this.populateAutoCompleteLists().pipe(
      takeUntil(this.destroyed$),
      switchMap(() => this.buildForm()),
      map((connectSessionForm) => this.connectSessionForm = connectSessionForm),
      switchMap(() => this.setHostnameDropdown()),
      switchMap(() => this.setupScreenSizeDropdown()),
      catchError(error => {
        console.error(error.message);
        return EMPTY;
      }),
    ).subscribe();
  }

  private populateAutoCompleteLists(): Observable<void> {
    this.hostnames = this.storageService.getItem<AutoCompleteInput[]>('hostnames');
    return of(undefined);
  }

  private setHostnameDropdown(): Observable<void> {
    if (!this.isFormExists && !this.inputFormData) {
      return of(undefined);
    }

    this.connectSessionForm.get('autoComplete').setValue(
      this.hostnames.find(hostnames =>
      hostnames.hostname === this.inputFormData?.autoComplete?.hostname));

    return of(undefined);
  }
  private setupScreenSizeDropdown(): Observable<void> {
    this.screenSizeOptions = ScreenSize.getSelectItems();
    this.subscribeToFormScreenSize();
    return of(undefined);
  }

  private subscribeToFormScreenSize(): void {
    this.connectSessionForm.get('screenSize').valueChanges.pipe(
      takeUntil(this.destroyed$),
    ).subscribe(value => {
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
