import { Component, computed, effect, inject } from '@angular/core';
import { CommonModule } from '@angular/common';
import { Router, RouterLink, RouterOutlet } from '@angular/router';
import { AuthService } from './auth/auth.service';

@Component({
  selector: 'app-root',
  standalone: true,
  imports: [CommonModule, RouterOutlet, RouterLink],
  templateUrl: './app.component.html',
  styleUrl: './app.component.css'
})
export class AppComponent {
  authService = inject(AuthService);
  router = inject(Router);

  // Use a signal to reactively check login status
  isLoggedIn = this.authService.isLoggedIn; 
  
  // Computed signal to check for admin role
  isAdmin = computed(() => this.authService.userRole() === 'admin');

  constructor() {
    // This effect will run whenever the isLoggedIn signal changes.
    effect(() => {
      console.log(`DEBUG: AppComponent effect - isLoggedIn status changed to:`, this.isLoggedIn());
      // If the user just logged in, navigate them to their profile.
      if (this.isLoggedIn()) {
        // Check if we are on a page that should be redirected away from after login
        if (this.router.url.includes('/login') || this.router.url.includes('/auth/callback')) {
           console.log(`DEBUG: AppComponent effect - User is logged in, redirecting to /profile from ${this.router.url}`);
           this.router.navigate(['/profile']);
        }
      }
    });
  }

  logout() {
    this.authService.logout();
    this.router.navigate(['/login']);
  }
}
