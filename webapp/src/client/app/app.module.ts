import { APP_BASE_HREF } from '@angular/common';
import { HTTP_INTERCEPTORS, provideHttpClient, withInterceptorsFromDi } from '@angular/common/http';
import { CUSTOM_ELEMENTS_SCHEMA, NgModule } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { BrowserModule } from '@angular/platform-browser';
import { BrowserAnimationsModule } from '@angular/platform-browser/animations';
import { ExtraOptions, RouterModule } from '@angular/router';
import { AuthInterceptor } from '@gateway/app-auth.interceptor';
import { MenuListActiveSessionsComponent } from '@gateway/modules/base/menu/menu-list-active-sessions/menu-list-active-sessions.component';
import { LoginComponent } from '@gateway/modules/login/login.component';
import { GatewayAlertMessageComponent } from '@shared/components/gateway-alert-message/gateway-alert-message.component';
import { GatewayAlertMessageService } from '@shared/components/gateway-alert-message/gateway-alert-message.service';
import { LoadingService } from '@shared/services/loading.service';
// Services
import { MainMenuService } from '@shared/services/main-menu.service';
import { SshKeyService } from '@shared/services/ssh-key.service';
import { WebClientService } from '@shared/services/web-client.service';
import { WebSessionService } from '@shared/services/web-session.service';
import { SharedModule } from '@shared/shared.module';
import { AutoCompleteModule } from 'primeng/autocomplete';
import { SidebarModule } from 'primeng/sidebar';
import { TabView, TabViewModule } from 'primeng/tabview';
import { ToastModule } from 'primeng/toast';
// Components
import { AppComponent } from './app.component';
// Other
import { routes } from './app.routes';
import { AppHeaderComponent } from './modules/base/header/app-header.component';
import { MainAppComponent } from './modules/base/main-app/main-app.component';
import { AppMenuComponent } from './modules/base/menu/app-menu.component';
import { MenuGroupListItemComponent } from './modules/base/menu/menu-group-list-item/menu-group-list-item.component';
import { MenuListItemComponent } from './modules/base/menu/menu-list-item/menu-list-item.component';

const routerOptions: ExtraOptions = {
  paramsInheritanceStrategy: 'always',
};

@NgModule({
  declarations: [
    AppComponent,
    LoginComponent,
    MainAppComponent,
    AppMenuComponent,
    AppHeaderComponent,
    MenuListItemComponent,
    MenuListActiveSessionsComponent,
    MenuGroupListItemComponent,
    GatewayAlertMessageComponent,
  ],
  schemas: [CUSTOM_ELEMENTS_SCHEMA],
  exports: [],
  bootstrap: [AppComponent],
  imports: [
    FormsModule,
    BrowserModule,
    BrowserAnimationsModule,
    RouterModule.forRoot(routes, routerOptions),
    SharedModule,
    SidebarModule,
    ToastModule,
    TabViewModule,
    AutoCompleteModule,
  ],
  providers: [
    { provide: HTTP_INTERCEPTORS, useClass: AuthInterceptor, multi: true },
    { provide: APP_BASE_HREF, useValue: '/jet/webapp/client/' },
    MainMenuService,
    GatewayAlertMessageService,
    LoadingService,
    WebSessionService,
    WebClientService,
    SshKeyService,
    TabView,
    provideHttpClient(withInterceptorsFromDi()),
  ],
})
export class AppModule {}
