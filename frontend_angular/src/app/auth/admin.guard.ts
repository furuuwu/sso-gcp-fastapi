import { inject } from '@angular/core';
import { CanActivateFn, Router } from '@angular/router';
import { AuthService } from './auth.service';

export const adminGuard: CanActivateFn = (route, state) => {
  const authService = inject(AuthService);
  const router = inject(Router);

  if (authService.userRole() === 'admin') {
    return true;
  }

  // Redirect to profile page if not an admin
  // You could also redirect to an "access-denied" page
  return router.parseUrl('/profile');
};