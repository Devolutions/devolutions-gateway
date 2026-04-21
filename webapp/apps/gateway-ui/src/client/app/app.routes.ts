import { Routes } from '@angular/router';

import { MainAppComponent } from '@gateway/modules/base/main-app/main-app.component';
import { LoginComponent } from '@gateway/modules/login/login.component';
import { authGuard } from '@shared/guards/auth.guard';

import { AgentEnrollmentComponent } from '@gateway/modules/web-client/agent-enrollment/agent-enrollment.component';

export const routes: Routes = [
  {
    path: '',
    redirectTo: 'session',
    pathMatch: 'full',
  },
  {
    path: 'session',
    component: MainAppComponent,
    canActivate: [authGuard],
    children: [
      {
        path: '',
        loadChildren: () => import('@gateway/modules/web-client/web-client.module').then((m) => m.WebClientModule),
        canActivate: [authGuard],
      },
      {
        path: 'agents',
        component: AgentEnrollmentComponent,
      },
    ],
  },
  { path: 'login', component: LoginComponent },
  { path: '**', redirectTo: 'session' },
];
