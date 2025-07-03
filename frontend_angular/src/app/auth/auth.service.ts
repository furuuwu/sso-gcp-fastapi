// Manages storing and retrieving the authentication token.

import { Injectable, signal, computed } from '@angular/core';
import { jwtDecode } from 'jwt-decode';

// This interface defines the structure of the data inside the JWT
interface UserPayload {
  sub: string; // Subject (usually the user's email)
  name: string;
  role: 'admin' | 'user';
  picture: string;
  exp: number; // Expiration time
}

@Injectable({
  providedIn: 'root'
})
export class AuthService {
  // The single source of truth for user data, initialized from sessionStorage.
  private userPayload = signal<UserPayload | null>(this.getDecodedTokenFromStorage());

  // --- Public signals derived from the userPayload ---

  // This signal is true if a user payload exists, false otherwise.
  // It will automatically update whenever userPayload changes.
  isLoggedIn = computed(() => !!this.userPayload());

  // This signal provides the user's role, or null if not logged in.
  userRole = computed(() => this.userPayload()?.role ?? null);
  
  // This provides the full decoded token for use in components like the profile page.
  decodedToken = computed(() => this.userPayload());

  constructor() {
    console.log("DEBUG: AuthService constructor. Initial isLoggedIn state:", this.isLoggedIn());
    // This makes your app sync auth state across multiple browser tabs.
    window.addEventListener('storage', (event) => {
      if (event.key === 'access_token') {
        this.userPayload.set(this.getDecodedTokenFromStorage());
      }
    });
  }

  /** Reads and decodes the token from session storage. */
  private getDecodedTokenFromStorage(): UserPayload | null {
    const token = sessionStorage.getItem('access_token');
    if (token) {
      try {
        // Check if token is expired
        const decoded = jwtDecode<UserPayload>(token);
        if (decoded.exp * 1000 > Date.now()) {
          return decoded;
        } else {
          sessionStorage.removeItem('access_token'); // Clean up expired token
          return null;
        }
      } catch (error) {
        console.error("Failed to decode token from storage", error);
        sessionStorage.removeItem('access_token'); // Clean up invalid token
        return null;
      }
    }
    return null;
  }

  /** Called from the callback component to store the new token. */
  setToken(token: string): void {
    console.log("DEBUG: AuthService setToken called.");
    sessionStorage.setItem('access_token', token);
    // This is the only place we need to set the signal.
    // All other signals (isLoggedIn, userRole) will update automatically.
    this.userPayload.set(this.getDecodedTokenFromStorage());
    console.log("DEBUG: New user payload set. isLoggedIn is now:", this.isLoggedIn());
  }

  /** Retrieves the raw token string. */
  getToken(): string | null {
    return sessionStorage.getItem('access_token');
  }

  /** Clears the token and user state. */
  logout(): void {
    sessionStorage.removeItem('access_token');
    this.userPayload.set(null);
  }
}
