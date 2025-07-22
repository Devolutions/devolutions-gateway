import { inject } from '@angular/core';
import { ActivatedRouteSnapshot, Router, RouterStateSnapshot } from '@angular/router';

import { AuthService } from '@shared/services/auth.service';

export function authGuard(_route: ActivatedRouteSnapshot, state: RouterStateSnapshot): boolean {
  const router: Router = inject(Router);
  const authService = inject(AuthService);

  if (authService.isAuthenticated) {
    return true;
  }

  void router.navigate(['login'], {
    queryParams: { returnUrl: state.url },
  });
  return false;
}
