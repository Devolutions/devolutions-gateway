import {NgModule, CUSTOM_ELEMENTS_SCHEMA} from '@angular/core';
import {RouterModule, Routes} from '@angular/router';
import {SharedModule} from '@shared/shared.module';
import {WebClientComponent} from './web-client.component';
import {WebClientRdpComponent} from './rdp/web-client-rdp.component';
import {RdpFormComponent} from "@gateway/modules/web-client/rdp/form/rdp-form.component";
import {TabViewComponent} from "@shared/components/tab-view/tab-view.component";
import {DynamicTabComponent} from "@shared/components/dynamic-tab/dynamic-tab.component";

const routes: Routes = [
  {
    path: '',
    component: WebClientComponent,
  }
];

@NgModule({
  imports: [
    RouterModule.forChild(routes),
    SharedModule
  ],
  schemas: [ CUSTOM_ELEMENTS_SCHEMA ],
  declarations: [
    WebClientComponent,
    WebClientRdpComponent,
    RdpFormComponent,
    TabViewComponent,
    DynamicTabComponent
  ],
    exports: [
      DynamicTabComponent
    ],
  providers: []
})

export class WebClientModule {
}
