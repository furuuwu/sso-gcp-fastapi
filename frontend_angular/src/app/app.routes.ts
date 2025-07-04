// frontend_angular/src/app.routes.ts
// Defines the application's routes, including the callback route.

import { Routes } from '@angular/router';
import { LoginComponent } from './login/login.component';
import { ProfileComponent } from './profile/profile.component';
import { AdminComponent } from './admin/admin.component';
import { AuthCallbackComponent } from './auth/auth-callback/auth-callback.component';
import { authGuard } from './auth/auth.guard';
import { adminGuard } from './auth/admin.guard';
import { ChatComponent } from './chat/chat.component';

export const routes: Routes = [
  { path: 'login', component: LoginComponent },
  { path: 'auth/callback', component: AuthCallbackComponent },
  
  // --- UPDATED ROUTES ---
  // A parent route protected by the authGuard.
  // If the guard passes, the router will process the child routes.
  // If it fails, the guard will redirect to '/login'.
  {
    path: '',
    canActivate: [authGuard],
    children: [
      {
        path: 'profile', 
        component: ProfileComponent
      },
      { 
        path: 'admin', 
        component: AdminComponent,
        canActivate: [adminGuard] // A second guard specific to this route
      },
      {
        path: 'chat',
        component: ChatComponent
      },
      // If an authenticated user navigates to the root path, redirect them to their profile.
      { 
        path: '', 
        redirectTo: 'profile', 
        pathMatch: 'full'
      }
    ]
  },
  
  // Wildcard route redirects to the guarded parent route. 
  // The guard will then decide if the user should see the profile or be sent to login.
  { path: '**', redirectTo: '' } 
];
