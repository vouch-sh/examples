import { bootstrapApplication } from '@angular/platform-browser';
import { provideRouter } from '@angular/router';
import { provideAuth, LogLevel } from 'angular-auth-oidc-client';
import { AppComponent } from './app/app.component';
import { routes } from './app/app.routes';

bootstrapApplication(AppComponent, {
  providers: [
    provideRouter(routes),
    provideAuth({
      config: {
        authority: '__VOUCH_ISSUER__',
        clientId: '__VOUCH_CLIENT_ID__',
        redirectUrl: '__VOUCH_REDIRECT_URI__',
        postLogoutRedirectUri: typeof window !== 'undefined' ? window.location.origin : '',
        scope: 'openid email',
        responseType: 'code',
        logLevel: LogLevel.Warn,
      },
    }),
  ],
});
