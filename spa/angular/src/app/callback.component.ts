import { Component, OnInit, inject, signal } from '@angular/core';
import { Router } from '@angular/router';
import { userManager } from './auth';

@Component({
  selector: 'app-callback',
  standalone: true,
  template: `
    @if (error()) {
      <p>Login failed: {{ error() }}. <a href="/">Try again</a></p>
    } @else {
      <p>Processing login...</p>
    }
  `,
})
export class CallbackComponent implements OnInit {
  private router = inject(Router);

  error = signal('');

  async ngOnInit() {
    try {
      await userManager.signinRedirectCallback();
      await this.router.navigateByUrl('/');
    } catch (err) {
      console.error('Login error:', err);
      this.error.set((err as Error).message);
    }
  }
}
