import { Component, OnInit, inject } from '@angular/core';
import { CommonModule } from '@angular/common';
import { RouterOutlet } from '@angular/router';
import { OidcSecurityService } from 'angular-auth-oidc-client';

// Display only -- never an authorization decision.
//
// This decodes the access token payload WITHOUT verifying its signature. A public
// client gains nothing by verifying a token it just received over TLS from the token
// endpoint, and shipping a JOSE library to the browser to do it would teach the wrong
// lesson. The security decision belongs to the resource server, which must verify the
// signature and the audience -- see mcp/remote-server-ts, or spa/bff-express for a
// backend that holds the tokens instead.
function decodeUnverifiedForDisplay(token: string): Record<string, unknown> {
  return JSON.parse(atob(token.split('.')[1].replace(/-/g, '+').replace(/_/g, '/')));
}

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
    this.oidc.checkAuth().subscribe(({ isAuthenticated, userData, accessToken }) => {
      this.isAuthenticated = isAuthenticated;
      if (userData) {
        this.email = userData.email || '';
      }
      if (accessToken) {
        const atClaims = decodeUnverifiedForDisplay(accessToken);
        this.hardwareVerified = (atClaims['hardware_verified'] as boolean) || false;
      }
      // After processing the callback, redirect to home with a full page load
      // so checkAuth() re-reads stored tokens and updates the UI
      if (window.location.pathname === '/callback') {
        window.location.href = '/';
      }
    });
  }

  login() {
    this.oidc.authorize();
  }

  logout() {
    this.oidc.logoffLocal();
    this.isAuthenticated = false;
    this.email = '';
    this.hardwareVerified = false;
  }
}
