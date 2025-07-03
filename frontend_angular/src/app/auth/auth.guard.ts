import { inject } from '@angular/core';
import { CanActivateFn, Router } from '@angular/router';
import { AuthService } from './auth.service';

export const authGuard: CanActivateFn = (route, state) => {
  const authService = inject(AuthService);
  const router = inject(Router);

  const isLoggedIn = authService.isLoggedIn();
  console.log(`DEBUG: authGuard checking for URL "${state.url}". isLoggedIn is:`, isLoggedIn);

  if (isLoggedIn) {
    return true;
  }

  // Redirect to the login page if not authenticated
  console.log("DEBUG: authGuard redirecting to /login");
  return router.parseUrl('/login');
};
