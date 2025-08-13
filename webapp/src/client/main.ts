import { APP_BASE_HREF } from '@angular/common';
import { HTTP_INTERCEPTORS, provideHttpClient, withInterceptorsFromDi } from '@angular/common/http';
import { bootstrapApplication, } from '@angular/platform-browser';
import { provideAnimationsAsync } from '@angular/platform-browser/animations/async';
import { AuthInterceptor } from '@gateway/app-auth.interceptor';
import { GatewayAlertMessageService } from '@shared/components/gateway-alert-message/gateway-alert-message.service';
import { LoadingService } from '@shared/services/loading.service';
// Services
import { MainMenuService } from '@shared/services/main-menu.service';
import { SshKeyService } from '@shared/services/ssh-key.service';
import { WebClientService } from '@shared/services/web-client.service';
import { WebSessionService } from '@shared/services/web-session.service';
// Components
import { provideRouter } from '@angular/router';
import { AppComponent } from '@gateway/app.component';
import { routes } from '@gateway/app.routes';
import { MessageService } from 'primeng/api';
// Prime Theme
import Aura from '@primeuix/themes/aura';
import {providePrimeNG} from "primeng/config";

bootstrapApplication(AppComponent, {
  providers: [
    { provide: HTTP_INTERCEPTORS, useClass: AuthInterceptor, multi: true },
    { provide: APP_BASE_HREF, useValue: '/jet/webapp/client/' },
    MainMenuService,
    GatewayAlertMessageService,
    LoadingService,
    WebSessionService,
    WebClientService,
    SshKeyService,
    MessageService,
    provideHttpClient(withInterceptorsFromDi()),
    provideRouter(routes),
    provideAnimationsAsync(),
    providePrimeNG({
      theme: {
        preset: Aura,
        options: {
          prefix: 'p',              // default CSS variable prefix
          darkModeSelector: 'system', // or your custom selector
          cssLayer: false           // optional layering
        }
      }
    }),
  ],
}).catch(err => console.error(err));
