import { inject } from '@angular/core';
import {Router, UrlTree} from '@angular/router';

import { AuthService } from "@shared/services/auth.service";

export const authGuard = (): boolean | UrlTree => {
  const authService: AuthService = inject(AuthService);
  const router: Router = inject(Router);

  if (authService.isLoggedIn) {
    return true;
  }

  return router.parseUrl('/login');
};
