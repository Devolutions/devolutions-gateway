import {Component, EventEmitter, Input, OnChanges, OnInit, Output, SimpleChanges} from '@angular/core';
import {AbstractControl, FormBuilder, FormControl, FormGroup, ValidatorFn, Validators} from "@angular/forms";
import {Message, SelectItem} from "primeng/api";
import {catchError, switchMap, takeUntil} from "rxjs/operators";
import {EMPTY, Observable, of} from "rxjs";

import {BaseComponent} from "@shared/bases/base.component";
import {WebSession} from "@shared/models/web-session.model";
import {ComponentStatus} from "@shared/models/component-status.model";
import {Protocol, WebClientProtocol} from "@shared/enums/web-client-protocol.enum";
import {AuthMode, WebClientAuthMode} from "@shared/enums/web-client-auth-mode.enum";
import {ScreenSize} from "@shared/enums/screen-size.enum";
import {StorageService} from "@shared/services/utils/storage.service";
import {WebSessionService} from "@shared/services/web-session.service";
import {AutoCompleteInput, HostnameObject} from "@shared/interfaces/forms.interfaces";
import {SelectItemWithTooltip} from "@shared/interfaces/select-item-tooltip.interface";


interface FormInputVisibility {
  showAuthModeInput?: boolean;
  showUsernameInput?: boolean;
  showPasswordInput?: boolean;
  showMoreSettingsInputs?: boolean;
}

@Component({
  selector: 'web-client-form',
  templateUrl: 'web-client-form.component.html',
  styleUrls: ['web-client-form.component.scss']
})
export class WebClientFormComponent extends BaseComponent implements  OnInit,
                                                                      OnChanges {

  @Input() isFormExists: boolean = false;
  @Input() webSessionId: string | undefined;
  @Input() inputFormData: any;
  @Input() error: string;

  @Output() componentStatus: EventEmitter<ComponentStatus> = new EventEmitter<ComponentStatus>();
  @Output() sizeChange: EventEmitter<void> = new EventEmitter<void>();

  private formInputVisibilityMap: { [key in Protocol]: FormInputVisibility } = {
    [Protocol.RDP]: { showUsernameInput: true, showPasswordInput: true, showMoreSettingsInputs: true },
    [Protocol.VNC]: { showAuthModeInput: true },
    [Protocol.SSH]: { showUsernameInput: true, showPasswordInput: true },
    [Protocol.ARD]: { showUsernameInput: true, showPasswordInput: true },
    [Protocol.Telnet]: {},
  };

  connectSessionForm: FormGroup;
  authModeOptions: SelectItem[];
  screenSizeOptions: SelectItem[];
  protocolOptions: SelectItemWithTooltip[];
  protocolSelectedTooltip: string = '';

  showMoreSettings: boolean = false;
  showPassword: boolean = false;

  messages: Message[] = [];

  hostnames!: HostnameObject[];
  filteredHostnames!: HostnameObject[];

  constructor(private webSessionService: WebSessionService,
              private storageService: StorageService,
              private formBuilder: FormBuilder) {
    super();
  }

  ngOnInit(): void {
    this.populateForm();
  }

  ngOnChanges(changes: SimpleChanges): void {
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

  showAuthModeInput(): boolean {
    return this.getCurrentProtocolInputVisibility().showAuthModeInput ?? false;
  }

  showUsernameInput(): boolean {
    return this.getCurrentProtocolInputVisibility().showUsernameInput ?? false;
  }

  showPasswordInput(): boolean {
    return this.getCurrentProtocolInputVisibility().showPasswordInput ?? false;
  }

  showMoreSettingsInputs(): boolean {
    return this.getCurrentProtocolInputVisibility().showMoreSettingsInputs ?? false;
  }

  onProtocolChange(value: any): void {
    this.updateProtocolTooltip(value);
  }

  onConnectSession(): void {
    this.webSessionService.createWebSession(this.connectSessionForm, this.getSelectedProtocol()).pipe(
      takeUntil(this.destroyed$),
      switchMap((webSession) => this.manageScreenSize(webSession)),
      switchMap((webSession) => this.manageWebSessionSubject(webSession))
    ).subscribe(
      (webSession) => {
        this.addHostnameToStorage(webSession?.data?.hostname);
      }
    );
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
    return this.hostnames?.length > 0;
  }

  filterHostname(event: any): void {
    const query = event.query.toLowerCase();

    this.filteredHostnames = this.hostnames?.filter(hostnameObj =>
      hostnameObj.hostname.toLowerCase().startsWith(query)
    );
  }

  private kdcServerUrlValidator(): ValidatorFn {
    return (control: AbstractControl): { [key: string]: any } | null => {
      if (!control.value) {
        return null;
      }

      const validTcpProtocol: boolean = /^(tcp|udp):\/\/.*$/.test(control.value);
      return validTcpProtocol ? null : { 'invalidKdcProtocol': { value: control.value } };
    };
  }

  private getCurrentProtocolInputVisibility(): FormInputVisibility {
    const currentProtocol: Protocol = this.getSelectedProtocol();
    const visibility: FormInputVisibility = this.formInputVisibilityMap[currentProtocol] || {};

    if (currentProtocol === Protocol.VNC) {
      const authMode: AuthMode = this.getSelectedAuthMode();
      return {
        ...visibility,
        showUsernameInput: authMode === AuthMode.Username_and_Password,
        showPasswordInput: [AuthMode.VNC_Password, AuthMode.Username_and_Password].includes(authMode),
      };
    }

    return visibility;
  }

  private updateProtocolTooltip(value: any): void {
  const selectedItem: SelectItemWithTooltip = this.protocolOptions
    .find(item => item.value === value);

  this.protocolSelectedTooltip = selectedItem ? (selectedItem as any).tooltipText : '';
}

  private manageScreenSize(webSession: WebSession<any, any>): Observable<WebSession<any, any>> {
    if (!this.isSelectedProtocolRdp()) {
      return of(webSession);
    }

    const formScreenSize: ScreenSize = webSession.data?.screenSize;
    if (formScreenSize === ScreenSize.FullScreen) {
      const width: number = window.screen.width;
      const height: number = window.screen.height;
      this.webSessionService.setWebSessionScreenSize({ width, height });
    } else {
      this.sizeChange.emit();
    }
    return of(webSession);
  }

  private manageWebSessionSubject(webSession: WebSession<any, any>): Observable<WebSession<any, any>> {
    if (this.isFormExists) {
      webSession.id = this.webSessionId;
      this.webSessionService.updateSession(webSession);
    } else {
      this.webSessionService.addSession(webSession);
    }
    return of(webSession);
  }

  private isSelectedProtocolRdp(): boolean {
    return this.getSelectedProtocol() === Protocol.RDP;
  }

  private isHostnameInArray(hostname: string, array: AutoCompleteInput[] = []): boolean {
    return array.some(obj => obj.hostname === hostname);
  }

  private processAutoCompleteInput(input: string | AutoCompleteInput): AutoCompleteInput {
    return typeof input === 'string' ? {'hostname': input} : input;
  }

  private addHostnameToStorage(hostname: string): void {
    try {
      if (!hostname) {
        return;
      }

      const hostnameObj: AutoCompleteInput = this.processAutoCompleteInput(hostname);
      const hostnames: AutoCompleteInput[] = this.storageService.getItem<AutoCompleteInput[]>('hostnames') ?? [];

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

  private buildForm(): Observable<void> {
    const formControls = {
      protocol: [0, Validators.required],
      autoComplete: new FormControl('', Validators.required),
      hostname: [''],
      authMode: [AuthMode.VNC_Password],
      username: ['', Validators.required],
      password: ['', Validators.required],
      screenSize: [null],
      customWidth: [{value: '', disabled: true}],
      customHeight: [{value: '', disabled: true}],
      kdcUrl: ['', [this.kdcServerUrlValidator()]],
      preConnectionBlob: ['']
    };

    const formGroup = this.formBuilder.group(formControls);

    if (this.isFormExists && this.inputFormData) {
      formGroup.patchValue({
        protocol: this.inputFormData.protocol,
        autoComplete: this.inputFormData.autoComplete,
        hostname: this.inputFormData.hostname,
        authMode: this.inputFormData.authMode,
        username: this.inputFormData.username,
        password: this.inputFormData.password,
        screenSize: this.inputFormData.screenSize,
        customWidth: this.inputFormData.customWidth, // Assuming you handle enabling/disabling based on conditions
        customHeight: this.inputFormData.customHeight,
        kdcUrl: this.inputFormData.kdcUrl,
        preConnectionBlob: this.inputFormData.preConnectionBlob
      });
    }

    this.connectSessionForm = formGroup;
    this.updateFormControls();

    return of(undefined);
  }

  private updateFormControls(protocol?: Protocol): void {
    protocol = protocol ?? this.getSelectedProtocol();

    const controlsToDisable: string[] = [
      'authMode',
      'username',
      'password',
      'screenSize',
      'customWidth',
      'customHeight',
      'kdcUrl',
      'preConnectionBlob'
    ];

    controlsToDisable.forEach(control => {
      this.connectSessionForm.get(control)?.disable();
    });

    const protocolControlMap: { [key in Protocol]?: string[] } = {
      [Protocol.SSH]: ['username', 'password'],
      [Protocol.VNC]: ['authMode', 'username', 'password', 'screenSize'],
      [Protocol.ARD]: ['username', 'password', 'screenSize'],
      [Protocol.RDP]: ['username', 'password', 'screenSize', 'customWidth', 'customHeight', 'kdcUrl', 'preConnectionBlob'],
    };

    protocolControlMap[protocol]?.forEach(control => {
      this.connectSessionForm.get(control)?.enable();
    });

    if (protocol === Protocol.VNC) {
      this.setAuthMode(this.getSelectedAuthMode() ?? AuthMode.VNC_Password);
      this.updateFormControlsByAuthMode();
    }
  }

  private updateFormControlsByAuthMode(authMode?: AuthMode): void {
    authMode = authMode ?? this.inputFormData?.authMode ?? AuthMode.VNC_Password;

    const controlsToDisable: string[] = ['username', 'password'];
    controlsToDisable.forEach(control => {
      this.connectSessionForm.get(control)?.disable();
    });

    switch (authMode) {
      case AuthMode.VNC_Password:
        this.connectSessionForm.get('password')?.enable();
        break;

      case AuthMode.Username_and_Password :
        this.connectSessionForm.get('username')?.enable();
        this.connectSessionForm.get('password')?.enable();
        break;

      case AuthMode.None:
        // AuthMode is None. No controls enabled. KAH Feb 23, 2024
        break;
    }
  }

  private populateForm(): void {
    this.populateAutoCompleteLists().pipe(
      takeUntil(this.destroyed$),
      switchMap(() => this.buildForm()),
      switchMap(() => this.setHostnameDropdown()),
      switchMap(() => this.setupAuthModeDropdown()),
      switchMap(() => this.setupScreenSizeDropdown()),
      switchMap(() => this.setupProtocolDropdown()),
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

  private getSelectedProtocol(): Protocol {
    return this.connectSessionForm.get('protocol').value;
  }

  private getSelectedAuthMode(): AuthMode {
    return this.connectSessionForm.get('authMode').value;
  }

  private setAuthMode(authMode: AuthMode = AuthMode.VNC_Password): void {
    this.connectSessionForm.patchValue({
      authMode: authMode
    });
  }

  private setHostnameDropdown(): Observable<void> {
    if (!this.isFormExists && !this.inputFormData) {
      return of(undefined);
    }

    this.connectSessionForm.get('autoComplete').setValue(
      this.hostnames.find(hostnames =>
        hostnames?.hostname === this.inputFormData?.autoComplete?.hostname));

    return of(undefined);
  }

  private setupAuthModeDropdown(): Observable<void> {
    this.authModeOptions = WebClientAuthMode.getSelectItems();
    this.subscribeToFormAuthMode();
    return of(undefined);
  }

  private setupScreenSizeDropdown(): Observable<void> {
    this.screenSizeOptions = ScreenSize.getSelectItems();
    this.subscribeToFormScreenSize();
    return of(undefined);
  }

  private setupProtocolDropdown(): Observable<void> {
    this.protocolOptions = WebClientProtocol.getSelectItems();
    this.updateProtocolTooltip(this.getSelectedProtocol());
    this.subscribeToFormProtocol();
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

  private subscribeToFormProtocol(): void {
    this.connectSessionForm.get('protocol').valueChanges.pipe(
      takeUntil(this.destroyed$),
    ).subscribe(value => {
      this.showMoreSettings = false;
      this.updateFormControls(value);
    });
  }

  private subscribeToFormAuthMode(): void {
    this.connectSessionForm.get('authMode').valueChanges.pipe(
      takeUntil(this.destroyed$),
    ).subscribe(value => {
      this.updateFormControlsByAuthMode(value);
    });
  }
}
