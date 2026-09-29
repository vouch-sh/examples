import { Component, OnDestroy, OnInit, computed, signal } from '@angular/core';
import { RouterOutlet } from '@angular/router';
import type { User } from 'oidc-client-ts';
import { getUser, userManager } from './auth';

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
  imports: [RouterOutlet],
  template: `
    <div style="font-family: system-ui; padding: 2rem">
      <h1>Vouch OIDC + Angular SPA</h1>

      @if (user(); as user) {
        <p>Signed in as {{ user.profile.email }}</p>
        @if (atClaims()['hardware_verified']) {
          <p><strong>Hardware Verified</strong></p>
        }
        <div style="margin-top: 1rem; padding: 1rem; background: #f0f8ff; border-radius: 4px">
          <h3>Profile Claims</h3>
          <ul style="list-style: none; padding: 0">
            <li><strong>sub:</strong> {{ user.profile.sub }}</li>
            <li><strong>email:</strong> {{ user.profile.email }}</li>
            @if (user.profile.email_verified !== undefined) {
              <li><strong>email_verified:</strong> {{ user.profile.email_verified }}</li>
            }
            <li><strong>hardware_verified:</strong> {{ atClaims()['hardware_verified'] || false }}</li>
            @if (atClaims()['acr']) {
              <li><strong>acr:</strong> {{ atClaims()['acr'] }}</li>
            }
            @if (amr().length) {
              <li><strong>amr:</strong> {{ amr().join(', ') }}</li>
            }
            @if (jkt()) {
              <li><strong>DPoP-bound (cnf.jkt):</strong> {{ jkt() }}</li>
            }
          </ul>
        </div>
        <div style="margin-top: 1rem; padding: 1rem; background: #f5f5f5; border-radius: 4px">
          <h3>Token Info</h3>
          <p>Token expires in: <strong>{{ timeLeft() }}s</strong></p>
        </div>
        <div style="margin-top: 1rem">
          <button (click)="logout()">Sign out</button>
        </div>
      } @else {
        <button (click)="login()">Sign in with Vouch</button>
      }

      <router-outlet></router-outlet>
    </div>
  `,
})
export class AppComponent implements OnInit, OnDestroy {
  private timer?: ReturnType<typeof setInterval>;
  private now = signal(Math.floor(Date.now() / 1000));

  user = signal<User | null>(null);
  atClaims = computed<Record<string, unknown>>(() => {
    const token = this.user()?.access_token;
    return token ? decodeUnverifiedForDisplay(token) : {};
  });
  amr = computed(() => (this.atClaims()['amr'] as string[] | undefined) ?? []);
  jkt = computed(() => (this.atClaims()['cnf'] as { jkt?: string } | undefined)?.jkt);
  timeLeft = computed(() => Math.max((this.user()?.expires_at ?? 0) - this.now(), 0));

  private onUserLoaded = (user: User) => this.user.set(user);
  private onExpired = async () => {
    await userManager.removeUser();
    this.user.set(null);
  };

  async ngOnInit() {
    // The callback route signs in after this component has loaded, so pick the user
    // up from the event rather than only on startup.
    userManager.events.addUserLoaded(this.onUserLoaded);
    userManager.events.addAccessTokenExpired(this.onExpired);
    this.timer = setInterval(() => this.now.set(Math.floor(Date.now() / 1000)), 1000);
    this.user.set(await getUser());
  }

  ngOnDestroy() {
    userManager.events.removeUserLoaded(this.onUserLoaded);
    userManager.events.removeAccessTokenExpired(this.onExpired);
    clearInterval(this.timer);
  }

  login() {
    userManager.signinRedirect();
  }

  // signoutRedirect, not removeUser: removeUser only clears local storage and leaves
  // the Vouch session intact, so the next sign-in completes silently.
  logout() {
    userManager.signoutRedirect();
  }
}
