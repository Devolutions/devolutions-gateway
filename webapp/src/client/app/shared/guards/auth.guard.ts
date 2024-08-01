import { inject } from '@angular/core';
import { ActivatedRouteSnapshot, Router, RouterStateSnapshot } from '@angular/router';

import { AuthService } from '@shared/services/auth.service';

export function authGuard(route: ActivatedRouteSnapshot, state: RouterStateSnapshot): boolean {
  const router: Router = inject(Router);
  const authService: AuthService = inject(AuthService);

  if (authService.isAuthenticated) {
    return true;
  }

  //TODO Add when standalone has more feature pages: { queryParams: { returnUrl: state.url } }
  router.navigate(['login']);
  return false;
}
