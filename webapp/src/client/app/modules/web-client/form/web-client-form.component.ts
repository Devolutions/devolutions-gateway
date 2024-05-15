import {
  ChangeDetectorRef,
  Component,
  EventEmitter,
  Input,
  OnChanges,
  OnInit,
  Output,
  SimpleChanges
} from '@angular/core';
import {AbstractControl, FormBuilder, FormControl, FormGroup, Validators} from "@angular/forms";
import {Message} from "primeng/api";
import {catchError, startWith, switchMap, takeUntil} from "rxjs/operators";
import {EMPTY, forkJoin, Observable, of} from "rxjs";

import {BaseComponent} from "@shared/bases/base.component";
import {WebSession} from "@shared/models/web-session.model";
import {ComponentStatus} from "@shared/models/component-status.model";
import {Protocol, WebClientProtocol} from "@shared/enums/web-client-protocol.enum";
import {ScreenSize} from "@shared/enums/screen-size.enum";
import {StorageService} from "@shared/services/utils/storage.service";
import {WebSessionService} from "@shared/services/web-session.service";
import {WebFormService} from "@shared/services/web-form.service";
import {AutoCompleteInput, HostnameObject} from "@shared/interfaces/forms.interfaces";
import {SelectItemWithTooltip} from "@shared/interfaces/select-item-tooltip.interface";
import {NetScanEntry, NetScanService} from '@gateway/shared/services/net-scan.services';
import {UtilsService} from "@shared/services/utils.service";

@Component({
  selector: 'web-client-form',
  templateUrl: 'web-client-form.component.html',
  styleUrls: ['web-client-form.component.scss'],
})
export class WebClientFormComponent
  extends BaseComponent
  implements OnInit, OnChanges
{
  @Input() isFormExists: boolean = false;
  @Input() webSessionId: string | undefined;
  @Input() inputFormData: any;
  @Input() error: any;

  @Output() componentStatus: EventEmitter<ComponentStatus> =
    new EventEmitter<ComponentStatus>();
  @Output() sizeChange: EventEmitter<void> = new EventEmitter<void>();

  connectSessionForm: FormGroup = this.fb.group({});

  protocolOptions: SelectItemWithTooltip[];
  protocolSelectedTooltip: string = '';

  messages: Message[] = [];

  hostnames!: HostnameObject[];
  filteredHostnames!: HostnameObject[];

  constructor(
    private fb: FormBuilder,
    private formService: WebFormService,
    private webSessionService: WebSessionService,
    private storageService: StorageService,
    private netscanService: NetScanService,
    protected utils: UtilsService,
    private cdr: ChangeDetectorRef
  ) {
    super();
  }

  ngOnInit(): void {
    this.initializeFormAndOptions();
    this.subscribeToNetscanFillEvent();
  }

  ngOnChanges(changes: SimpleChanges): void {
    if (changes.error && this.error) {
      this.displayErrorMessages(this.error);
    }
  }

  onConnectSession(): void {
    this.webSessionService
      .createWebSession(
        this.connectSessionForm,
        this.getSelectedProtocol(),
        this.formService.getExtraSessionParameter()
      )
      .pipe(
        takeUntil(this.destroyed$),
        switchMap((webSession) => this.manageScreenSize(webSession)),
        switchMap((webSession) => this.manageWebSessionSubject(webSession)),
        catchError((error) => {
          console.error('Failed to process web session:', error);
          return EMPTY;
        })
      )
      .subscribe((webSession) => {
        this.addHostnameToStorage(webSession?.data?.hostname);
      });
  }

  isHostnamesExists(): boolean {
    return this.hostnames?.length > 0;
  }

  filterHostname(event: any): void {
    const query = event.query.toLowerCase();

    Promise.resolve().then(() => {
      this.filteredHostnames =
        this.hostnames?.filter((hostnameObj) =>
          hostnameObj.hostname.toLowerCase().startsWith(query)
        ) || [];
    });
  }

  private subscribeToProtocolChanges(): void {
    const protocolControl: AbstractControl<any, any> =
      this.connectSessionForm.get('protocol');
    if (!protocolControl) {
      return;
    }

    protocolControl.valueChanges
      .pipe(
        startWith(protocolControl.value as Protocol),
        takeUntil(this.destroyed$)
      )
      .subscribe(
        (protocol) => {
          const exceptions: string[] = [
            'protocol',
            'autoComplete',
            'hostname',
            'authMode',
          ];
          Object.keys(this.connectSessionForm.controls).forEach((key) => {
            if (!exceptions.includes(key)) {
              this.connectSessionForm.get(key).disable();
            }
          });

          this.formService.detectFormChanges(this.cdr);
        },
        (error) =>
          console.error('Error subscribing to protocol changes:', error)
      );
  }

  private initializeFormAndOptions(): void {
    this.buildFormGroup(this.inputFormData)
      .pipe(
        takeUntil(this.destroyed$),
        switchMap((formGroup) => {
          this.connectSessionForm = formGroup;
          this.subscribeToProtocolChanges();

          return forkJoin({
            protocolOptions: this.formService.getProtocolOptions(),
            hostnames: this.getHostnames(),
          });
        }),
        catchError((error) => {
          console.error('Initialization failed', error);
          return [];
        })
      )
      .subscribe({
        next: ({ protocolOptions, hostnames }) => {
          this.protocolOptions = protocolOptions;
          this.hostnames = hostnames;

          this.updateProtocolTooltip();
        },
        error: (error) =>
          console.error('Error fetching dropdown options', error),
      });
  }

  private buildFormGroup(inputFormData?: any): Observable<FormGroup> {
    const formControls = {
      protocol: [inputFormData?.protocol || 0, Validators.required],
      autoComplete: [inputFormData?.autoComplete || '', Validators.required],
      hostname: [inputFormData?.autoComplete || ''],
    };

    const formGroup = this.fb.group(formControls);
    return of(formGroup);
  }

  private getHostnames(): Observable<HostnameObject[]> {
    return of(this.storageService.getItem<AutoCompleteInput[]>('hostnames'));
  }

  private isHostnameInArray(
    hostname: string,
    array: AutoCompleteInput[] = []
  ): boolean {
    return array.some((obj) => obj.hostname === hostname);
  }

  private processHostnameInput(
    input: string | AutoCompleteInput
  ): AutoCompleteInput {
    return typeof input === 'string' ? { hostname: input } : input;
  }

  private addHostnameToStorage(hostname: string): void {
    try {
      if (!hostname) {
        return;
      }

      const hostnameObj: AutoCompleteInput =
        this.processHostnameInput(hostname);
      const hostnames: AutoCompleteInput[] =
        this.storageService.getItem<AutoCompleteInput[]>('hostnames') ?? [];

      if (!this.isHostnameInArray(hostnameObj.hostname, hostnames)) {
        hostnames.push(hostnameObj);
        this.storageService.setItem('hostnames', hostnames);
        this.populateHostnameList();
      }
    } catch (e) {
      console.error(e);
    }
  }

  private populateHostnameList(): Observable<void> {
    this.hostnames =
      this.storageService.getItem<AutoCompleteInput[]>('hostnames');
    return of(undefined);
  }

  private updateProtocolTooltip(value?: any): void {
    if (!value && this.protocolOptions.length > 0) {
      value = this.protocolOptions[0].value;
    }
    const selectedItem: SelectItemWithTooltip = this.protocolOptions.find(
      (item) => item.value === value
    );
    this.protocolSelectedTooltip = selectedItem
      ? (selectedItem as any).tooltipText
      : '';
  }

  private manageScreenSize(
    webSession: WebSession<any, any>
  ): Observable<WebSession<any, any>> {
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

  private manageWebSessionSubject(
    webSession: WebSession<any, any>
  ): Observable<WebSession<any, any>> {
    if (this.isFormExists) {
      webSession.id = this.webSessionId;
      this.webSessionService.updateSession(webSession);
    } else {
      this.webSessionService.addSession(webSession);
    }
    return of(webSession);
  }

  isSelectedProtocolRdp(): boolean {
    return WebClientProtocol.isProtocolRdp(this.getSelectedProtocol());
  }

  isSelectedProtocolSsh(): boolean {
    return WebClientProtocol.isProtocolSsh(this.getSelectedProtocol());
  }

  isSelectedProtocolVnc(): boolean {
    return WebClientProtocol.isProtocolVnc(this.getSelectedProtocol());
  }

  isSelectedProtocolArd(): boolean {
    return WebClientProtocol.isProtocolArd(this.getSelectedProtocol());
  }

  private addMessages(newMessages: Message[]): void {
    const areThereNewMessages: boolean = newMessages.some(
      (newMsg) =>
        !this.messages.some(
          (existingMsg) =>
            existingMsg.summary === newMsg.summary &&
            existingMsg.detail === newMsg.detail
        )
    );

    if (areThereNewMessages) {
      this.messages = [...this.messages, ...newMessages];
    }
  }

  private getSelectedProtocol(): Protocol {
    return this.connectSessionForm.get('protocol').value;
  }

  private displayErrorMessages(error: any): void {

    const formattedSummary: string = this.utils.string.replaceNewlinesWithBR(error['kind'] ?? error);
    const formattedDetail: string = this.utils.string.replaceNewlinesWithBR(error['backtrace'] ?? '');

    setTimeout(() => {
      this.addMessages([
        {
          severity: 'error',
          summary: formattedSummary,
          detail: formattedDetail,
        },
      ]);
    }, 500);
  }

  canConnect(): boolean {
    return this.formService.canConnect(this.connectSessionForm);
  }

  subscribeToNetscanFillEvent(): void {
    this.netscanService.onServiceSelected().subscribe((entry: NetScanEntry) => {
      this.connectSessionForm.get('hostname')?.setValue(entry.ip)
      this.connectSessionForm.get('autoComplete')?.setValue({
        hostname: entry.ip
      })

      let protocol: AbstractControl<any, any> = this.connectSessionForm.get('protocol')
      if (protocol && protocol.value!==entry.protocol) {
        protocol.setValue(entry.protocol)
      }
    });
  }
}
