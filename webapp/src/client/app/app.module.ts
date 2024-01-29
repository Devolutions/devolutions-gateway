import { FormsModule } from '@angular/forms';
import {CUSTOM_ELEMENTS_SCHEMA, NgModule} from '@angular/core';
import {APP_BASE_HREF} from "@angular/common";
import { BrowserModule } from '@angular/platform-browser';
import { RouterModule } from "@angular/router";
import { BrowserAnimationsModule } from '@angular/platform-browser/animations'; // Import BrowserAnimationsModule
import { HTTP_INTERCEPTORS, HttpClientModule } from '@angular/common/http';

// Components
import { AppComponent } from './app.component';
import { LoginComponent } from "@gateway/modules/login/login.component";
import { MainAppComponent } from "./modules/base/main-app/main-app.component";
import { AppMenuComponent } from './modules/base/menu/app-menu.component';
import { MenuListItemComponent } from './modules/base/menu/menu-list-item/menu-list-item.component';
import { MenuListActiveSessionsComponent } from "@gateway/modules/base/menu/menu-list-active-sessions/menu-list-active-sessions.component";
import { MenuGroupListItemComponent } from './modules/base/menu/menu-group-list-item/menu-group-list-item.component';
import { AppHeaderComponent } from './modules/base/header/app-header.component';
import {GatewayAlertMessageComponent} from "@shared/components/gateway-alert-message/gateway-alert-message.component";

// Services
import { MainMenuService } from "@shared/services/main-menu.service";
import { GatewayAlertMessageService } from "@shared/components/gateway-alert-message/gateway-alert-message.service";
import { LoadingService} from "@shared/services/loading.service";
import { WebSessionService } from "@shared/services/web-session.service";

// Other
import { routes } from './app.routes';
import { SharedModule } from "@shared/shared.module";
import { AuthInterceptor } from "@gateway/app-auth.interceptor";
import { SidebarModule } from "primeng/sidebar";
import { ToastModule } from "primeng/toast";
import { TabView, TabViewModule } from "primeng/tabview";
import { AutoCompleteModule } from "primeng/autocomplete";


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
    GatewayAlertMessageComponent
  ],
  schemas: [CUSTOM_ELEMENTS_SCHEMA],
  imports: [
    FormsModule,
    BrowserModule,
    BrowserAnimationsModule,
    RouterModule.forRoot(routes),
    HttpClientModule,
    SharedModule,
    SidebarModule,
    ToastModule,
    TabViewModule,
    AutoCompleteModule
  ],
  providers: [
    { provide: HTTP_INTERCEPTORS, useClass: AuthInterceptor, multi: true },
    { provide: APP_BASE_HREF, useValue: '/jet/webapp/client/' },
    MainMenuService,
    GatewayAlertMessageService,
    LoadingService,
    WebSessionService,
    TabView
  ],
  exports: [
  ],
  bootstrap: [AppComponent]
})
export class AppModule { }
