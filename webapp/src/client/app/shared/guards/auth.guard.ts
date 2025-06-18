import { inject } from '@angular/core';
import { ActivatedRouteSnapshot, Router, RouterStateSnapshot } from '@angular/router';

import { AuthService } from '@shared/services/auth.service';

export function authGuard(_route: ActivatedRouteSnapshot, _state: RouterStateSnapshot): boolean {
  const router: Router = inject(Router);
  const authService = inject(AuthService);

  if (authService.isAuthenticated) {
    return true;
  }

  //TODO Add when standalone has more feature pages: { queryParams: { returnUrl: state.url } }
  void router.navigate(['login']);
  return false;
}
