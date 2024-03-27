import {NgModule, CUSTOM_ELEMENTS_SCHEMA} from '@angular/core';
import {KeyFilterModule} from "primeng/keyfilter";
import {RouterModule, Routes} from '@angular/router';

import {SharedModule} from '@shared/shared.module';
import {WebClientComponent} from './web-client.component';
import {WebClientRdpComponent} from './rdp/web-client-rdp.component';
import {WebClientVncComponent} from "@gateway/modules/web-client/vnc/web-client-vnc.component";
import {WebClientArdComponent} from "@gateway/modules/web-client/ard/web-client-ard.component";
import {WebClientTelnetComponent} from "@gateway/modules/web-client/telnet/web-client-telnet.component";
import {WebClientSshComponent} from "@gateway/modules/web-client/ssh/web-client-ssh.component";
import {WebClientFormComponent} from "@gateway/modules/web-client/form/web-client-form.component";
import {TabViewComponent} from "@shared/components/tab-view/tab-view.component";
import {DynamicTabComponent} from "@shared/components/dynamic-tab/dynamic-tab.component";
import {SessionToolbarComponent} from "@shared/components/session-toolbar/session-toolbar.component";
import {RdpFormComponent} from "@gateway/modules/web-client/form/form-components/rdp/rdp-form.component";
import {SshFormComponent} from "@gateway/modules/web-client/form/form-components/ssh/ssh-form.component";
import {VncFormComponent} from "@gateway/modules/web-client/form/form-components/vnc/vnc-form.component";
import {ArdFormComponent} from "@gateway/modules/web-client/form/form-components/ard/ard-form.component";
import {
  UsernameControlComponent
} from "@gateway/modules/web-client/form/form-controls/username-control/username-control.component";
import {
  PasswordControlComponent
} from "@gateway/modules/web-client/form/form-controls/password-control/password-control.component";
import {
  ScreenSizeControlComponent
} from "@gateway/modules/web-client/form/form-controls/screen-size-control/screen-size-control.component";
import {
  KdcUrlControlComponent
} from "@gateway/modules/web-client/form/form-controls/kdc-url-control/kdc-url-control.component";
import {
  PreConnectionBlobControlComponent
} from "@gateway/modules/web-client/form/form-controls/preconnection-blob/pre-connection-blob-control.component";
import { FileControlComponent } from './form/form-controls/file-control/file-control.component';


const routes: Routes = [
  {
    path: '',
    component: WebClientComponent,
  }
];

@NgModule({
    imports: [
        RouterModule.forChild(routes),
        SharedModule,
        KeyFilterModule
    ],
  schemas: [ CUSTOM_ELEMENTS_SCHEMA ],
  declarations: [
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
    FileControlComponent
  ],
    exports: [
      DynamicTabComponent
    ],
  providers: []
})

export class WebClientModule {
}
