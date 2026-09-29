import { Component, OnDestroy, OnInit, inject, signal } from '@angular/core';
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
        <div style="margin-top: 1rem; padding: 1rem; background: #f0f8ff; border-radius: 4px">
          <h3>Profile Claims</h3>
          <ul style="list-style: none; padding: 0">
            <li><strong>sub:</strong> {{ sub }}</li>
            <li><strong>email:</strong> {{ email }}</li>
            <li *ngIf="emailVerified !== undefined"><strong>email_verified:</strong> {{ emailVerified }}</li>
            <li><strong>hardware_verified:</strong> {{ hardwareVerified }}</li>
            <li *ngIf="acr"><strong>acr:</strong> {{ acr }}</li>
            <li *ngIf="amr.length"><strong>amr:</strong> {{ amr.join(', ') }}</li>
          </ul>
        </div>
        <div style="margin-top: 1rem; padding: 1rem; background: #f5f5f5; border-radius: 4px">
          <h3>Token Info</h3>
          <p>Token expires in: <strong>{{ timeLeft() }}s</strong></p>
        </div>
        <div style="margin-top: 1rem">
          <button (click)="logout()">Sign out</button>
        </div>
      </div>

      <ng-template #loginBlock>
        <button (click)="login()">Sign in with Vouch</button>
      </ng-template>

      <router-outlet></router-outlet>
    </div>
  `,
})
export class AppComponent implements OnInit, OnDestroy {
  private oidc = inject(OidcSecurityService);
  private timer?: ReturnType<typeof setInterval>;

  isAuthenticated = false;
  sub = '';
  email = '';
  emailVerified?: boolean;
  hardwareVerified = false;
  acr = '';
  amr: string[] = [];
  timeLeft = signal(0);

  ngOnInit() {
    this.oidc.checkAuth().subscribe(({ isAuthenticated, userData, accessToken }) => {
      this.isAuthenticated = isAuthenticated;
      if (userData) {
        this.sub = userData.sub || '';
        this.email = userData.email || '';
        this.emailVerified = userData.email_verified;
      }
      if (accessToken) {
        const atClaims = decodeUnverifiedForDisplay(accessToken);
        this.hardwareVerified = (atClaims['hardware_verified'] as boolean) || false;
        this.acr = (atClaims['acr'] as string) || '';
        this.amr = (atClaims['amr'] as string[]) || [];
        const exp = atClaims['exp'] as number;
        const tick = () => this.timeLeft.set(Math.max(exp - Math.floor(Date.now() / 1000), 0));
        tick();
        this.timer = setInterval(tick, 1000);
      }
      // After processing the callback, redirect to home with a full page load
      // so checkAuth() re-reads stored tokens and updates the UI
      if (window.location.pathname === '/callback') {
        window.location.href = '/';
      }
    });
  }

  ngOnDestroy() {
    clearInterval(this.timer);
  }

  login() {
    this.oidc.authorize();
  }

  // logoff, not logoffLocal: logoffLocal only clears local storage and leaves the
  // Vouch session intact, so the next sign-in completes silently.
  logout() {
    this.oidc.logoff().subscribe();
    this.isAuthenticated = false;
    this.email = '';
    this.hardwareVerified = false;
  }
}
