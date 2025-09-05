import { NgOptimizedImage } from '@angular/common';
import { CUSTOM_ELEMENTS_SCHEMA, NgModule } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { RouterModule, Routes } from '@angular/router';
import { WebClientArdComponent } from '@gateway/modules/web-client/ard/web-client-ard.component';
import { ArdFormComponent } from '@gateway/modules/web-client/form/form-components/ard/ard-form.component';
import { RdpFormComponent } from '@gateway/modules/web-client/form/form-components/rdp/rdp-form.component';
import { SshFormComponent } from '@gateway/modules/web-client/form/form-components/ssh/ssh-form.component';
import { VncFormComponent } from '@gateway/modules/web-client/form/form-components/vnc/vnc-form.component';
import { EnableCursorControlComponent } from '@gateway/modules/web-client/form/form-controls/enable-cursor-control/enable-cursor-control.component';
import { EnableDisplayConfigurationControlComponent } from '@gateway/modules/web-client/form/form-controls/enable-display-configuration-control/enable-display-configuration-control.component';
import { KdcUrlControlComponent } from '@gateway/modules/web-client/form/form-controls/kdc-url-control/kdc-url-control.component';
import { PasswordControlComponent } from '@gateway/modules/web-client/form/form-controls/password-control/password-control.component';
import { PreConnectionBlobControlComponent } from '@gateway/modules/web-client/form/form-controls/preconnection-blob/pre-connection-blob-control.component';
import { ScreenSizeControlComponent } from '@gateway/modules/web-client/form/form-controls/screen-size-control/screen-size-control.component';
import { UsernameControlComponent } from '@gateway/modules/web-client/form/form-controls/username-control/username-control.component';
import { WebClientFormComponent } from '@gateway/modules/web-client/form/web-client-form.component';
import { WebClientSshComponent } from '@gateway/modules/web-client/ssh/web-client-ssh.component';
import { WebClientTelnetComponent } from '@gateway/modules/web-client/telnet/web-client-telnet.component';
import { WebClientVncComponent } from '@gateway/modules/web-client/vnc/web-client-vnc.component';
import { WasmInitResolver } from '@gateway/shared/resolvers/wasm-init.resolver';
import { DynamicTabComponent } from '@shared/components/dynamic-tab/dynamic-tab.component';
import { MainPanelComponent } from '@shared/components/main-panel/main-panel.component';
import { SessionToolbarComponent } from '@shared/components/session-toolbar/session-toolbar.component';
import { TabViewComponent } from '@shared/components/tab-view/tab-view.component';
import { SharedModule } from '@shared/shared.module';
import { CheckboxModule } from 'primeng/checkbox';
import { KeyFilterModule } from 'primeng/keyfilter';
import { ArdQualityModeControlComponent } from './form/form-controls/ard-quality-mode-control/ard-quality-mode-control.component';
import { AutoClipboardControlComponent } from './form/form-controls/auto-clipboard-control/auto-clipboard-control.component';
import { ColorFormatControlComponent } from './form/form-controls/color-format-control/color-format-control.component';
// TODO: uncomment when adding support for iDRAC and VMWare
// import { VmIdControlComponent } from './form/form-controls/vm-id-control/vm-id-control.component';
// import { ForceFirmwareV7ControlComponent } from './form/form-controls/force-firmware-v7-control/force-firmware-v7-control.component';
// import { ForceWsPortControlComponent } from './form/form-controls/force-ws-port-control/force-ws-port-control.component';
// import { RequestSharedSessionControlComponent } from './form/form-controls/request-shared-session-control/request-shared-session-control.component';
// import { SharingApprovalModeControlComponent } from './form/form-controls/sharing-approval-mode-control/sharing-approval-mode-control.component';
import { EnabledEncodingsControlComponent } from './form/form-controls/enabled-encodings-control/enabled-encodings-control.component';
import { ExtendedClipboardControlComponent } from './form/form-controls/extended-clipboard-control/extended-clipboard-control.component';
import { FileControlComponent } from './form/form-controls/file-control/file-control.component';
import { ResolutionQualityControlComponent } from './form/form-controls/resolution-quality-control/resolution-quality-control.component';
import { UltraVirtualDisplayControlComponent } from './form/form-controls/ultra-virtual-display-control/ultra-virtual-display-control.component';
import { NetScanComponent } from './net-scan/net-scan.component';
import { WebClientRdpComponent } from './rdp/web-client-rdp.component';
import { WebClientComponent } from './web-client.component';

const routes: Routes = [
  {
    path: '',
    component: WebClientComponent,
    resolve: {
      wasmInit: WasmInitResolver,
    },
  },
];

@NgModule({
  imports: [
    RouterModule.forChild(routes),
    SharedModule,
    KeyFilterModule,
    FormsModule,
    NgOptimizedImage,
    CheckboxModule,
  ],
  schemas: [CUSTOM_ELEMENTS_SCHEMA],
  declarations: [
    MainPanelComponent,
    WebClientComponent,
    WebClientRdpComponent,
    WebClientVncComponent,
    WebClientTelnetComponent,
    WebClientSshComponent,
    WebClientArdComponent,
    WebClientFormComponent,
    RdpFormComponent,
    SshFormComponent,
    VncFormComponent,
    ArdFormComponent,
    UsernameControlComponent,
    PasswordControlComponent,
    ExtendedClipboardControlComponent,
    ScreenSizeControlComponent,
    EnableDisplayConfigurationControlComponent,
    KdcUrlControlComponent,
    PreConnectionBlobControlComponent,
    EnabledEncodingsControlComponent,
    ColorFormatControlComponent,
    EnableCursorControlComponent,
    AutoClipboardControlComponent,
    // TODO: iDRAC and VMWare support
    // VmIdControlComponent,
    // ForceFirmwareV7ControlComponent,
    // ForceWsPortControlComponent,
    // RequestSharedSessionControlComponent,
    // SharingApprovalModeControlComponent,
    UltraVirtualDisplayControlComponent,
    ResolutionQualityControlComponent,
    ArdQualityModeControlComponent,
    TabViewComponent,
    DynamicTabComponent,
    SessionToolbarComponent,
    FileControlComponent,
    NetScanComponent,
  ],
  exports: [DynamicTabComponent, WebClientFormComponent, NetScanComponent],
  providers: [],
})
export class WebClientModule {}
