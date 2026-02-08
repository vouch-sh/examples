import { Component, OnInit, inject } from '@angular/core';
import { CommonModule } from '@angular/common';
import { RouterOutlet } from '@angular/router';
import { OidcSecurityService } from 'angular-auth-oidc-client';

@Component({
  selector: 'app-root',
  standalone: true,
  imports: [CommonModule, RouterOutlet],
  template: `
    <div style="font-family: system-ui; padding: 2rem">
      <h1>Vouch OIDC + Angular SPA</h1>

      <div *ngIf="isAuthenticated; else loginBlock">
        <p>Signed in as {{ email }}</p>
        <p *ngIf="hardwareVerified"><strong>Hardware Verified</strong></p>
        <button (click)="logout()">Sign out</button>
      </div>

      <ng-template #loginBlock>
        <button (click)="login()">Sign in with Vouch</button>
      </ng-template>

      <router-outlet></router-outlet>
    </div>
  `,
})
export class AppComponent implements OnInit {
  private oidc = inject(OidcSecurityService);

  isAuthenticated = false;
  email = '';
  hardwareVerified = false;

  ngOnInit() {
    this.oidc.checkAuth().subscribe(({ isAuthenticated, userData }) => {
      this.isAuthenticated = isAuthenticated;
      if (userData) {
        this.email = userData.email || '';
        this.hardwareVerified = userData.hardware_verified || false;
      }
    });
  }

  login() {
    this.oidc.authorize();
  }

  logout() {
    this.oidc.logoff().subscribe();
  }
}
