import { CUSTOM_ELEMENTS_SCHEMA, NgModule } from '@angular/core';
import { RouterModule, Routes } from '@angular/router';
import { KeyFilterModule } from 'primeng/keyfilter';

import { NgOptimizedImage } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { WebClientArdComponent } from '@gateway/modules/web-client/ard/web-client-ard.component';
import { ArdFormComponent } from '@gateway/modules/web-client/form/form-components/ard/ard-form.component';
import { RdpFormComponent } from '@gateway/modules/web-client/form/form-components/rdp/rdp-form.component';
import { SshFormComponent } from '@gateway/modules/web-client/form/form-components/ssh/ssh-form.component';
import { VncFormComponent } from '@gateway/modules/web-client/form/form-components/vnc/vnc-form.component';
import { KdcUrlControlComponent } from '@gateway/modules/web-client/form/form-controls/kdc-url-control/kdc-url-control.component';
import { PasswordControlComponent } from '@gateway/modules/web-client/form/form-controls/password-control/password-control.component';
import { PreConnectionBlobControlComponent } from '@gateway/modules/web-client/form/form-controls/preconnection-blob/pre-connection-blob-control.component';
import { ScreenSizeControlComponent } from '@gateway/modules/web-client/form/form-controls/screen-size-control/screen-size-control.component';
import { UsernameControlComponent } from '@gateway/modules/web-client/form/form-controls/username-control/username-control.component';
import { WebClientFormComponent } from '@gateway/modules/web-client/form/web-client-form.component';
import { WebClientSshComponent } from '@gateway/modules/web-client/ssh/web-client-ssh.component';
import { WebClientTelnetComponent } from '@gateway/modules/web-client/telnet/web-client-telnet.component';
import { WebClientVncComponent } from '@gateway/modules/web-client/vnc/web-client-vnc.component';
import { DynamicTabComponent } from '@shared/components/dynamic-tab/dynamic-tab.component';
import { MainPanelComponent } from '@shared/components/main-panel/main-panel.component';
import { SessionToolbarComponent } from '@shared/components/session-toolbar/session-toolbar.component';
import { TabViewComponent } from '@shared/components/tab-view/tab-view.component';
import { SharedModule } from '@shared/shared.module';
import { FileControlComponent } from './form/form-controls/file-control/file-control.component';
import { NetScanComponent } from './net-scan/net-scan.component';
import { WebClientRdpComponent } from './rdp/web-client-rdp.component';
import { WebClientComponent } from './web-client.component';

const routes: Routes = [
  {
    path: '',
    component: WebClientComponent,
  },
];

@NgModule({
  imports: [RouterModule.forChild(routes), SharedModule, KeyFilterModule, FormsModule, NgOptimizedImage],
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
    ScreenSizeControlComponent,
    KdcUrlControlComponent,
    PreConnectionBlobControlComponent,
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
