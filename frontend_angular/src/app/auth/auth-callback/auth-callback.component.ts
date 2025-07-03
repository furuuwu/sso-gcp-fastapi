import { Component, OnInit, inject } from '@angular/core';
import { ActivatedRoute, Router } from '@angular/router';
import { AuthService } from '../auth.service';
import { CommonModule } from '@angular/common';

@Component({
  selector: 'app-auth-callback',
  standalone: true,
  imports: [CommonModule],
  template: '<p class="text-center text-gray-500">Processing login, please wait...</p>',
})
export class AuthCallbackComponent implements OnInit {
  private route = inject(ActivatedRoute);
  private authService = inject(AuthService);
  private router = inject(Router);

  ngOnInit(): void {
    console.log("DEBUG: AuthCallbackComponent ngOnInit fired.");
    
    // The token is in the URL fragment (#). We need to parse it manually.
    const fragment = this.route.snapshot.fragment;
    if (fragment) {
      console.log("DEBUG: Found URL fragment:", fragment);
      const params = new URLSearchParams(fragment);
      const token = params.get('access_token');

      if (token) {
        console.log("DEBUG: Token found in fragment. Calling setToken.");
        this.authService.setToken(token);
        // REMOVED: The router.navigate call is now handled by an effect in AppComponent.
        // This component's job is now complete.
      } else {
        console.error("DEBUG: Fragment found, but no access_token in it.");
        this.router.navigate(['/login']); // Redirect on failure
      }
    } else {
        console.error("DEBUG: No URL fragment found. Cannot process login.");
        this.router.navigate(['/login']); // Redirect on failure
    }
  }
}
