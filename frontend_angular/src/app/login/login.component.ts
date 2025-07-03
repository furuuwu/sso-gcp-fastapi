import { Component } from '@angular/core';
import { CommonModule } from '@angular/common';

@Component({
  selector: 'app-login',
  standalone: true,
  imports: [CommonModule],
  templateUrl: './login.component.html',
})
export class LoginComponent {
  // In a real app, this would come from an environment file
  readonly backendUrl = 'http://localhost:8000'; 

  login(): void {
    window.location.href = `${this.backendUrl}/api/auth/login`;
  }
}