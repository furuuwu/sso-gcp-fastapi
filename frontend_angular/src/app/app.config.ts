import { ApplicationConfig, provideZoneChangeDetection } from '@angular/core';
import { provideRouter, withComponentInputBinding } from '@angular/router';
import { provideHttpClient, withInterceptors } from '@angular/common/http';

import { routes } from './app.routes';
import { authInterceptor } from './auth/auth.interceptor';

export const appConfig: ApplicationConfig = {
  providers: [
    // Zone.js-based change detection strategy.
    provideZoneChangeDetection({ eventCoalescing: true }),

    // Sets up the application's routes
    provideRouter(routes, withComponentInputBinding()),
    
    // Configures HttpClient to use the functional interceptor
    provideHttpClient(withInterceptors([authInterceptor]))
  ]
};

