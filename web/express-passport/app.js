const express = require('express');
const session = require('express-session');
const passport = require('passport');
const OpenIDConnectStrategy = require('passport-openidconnect');

const app = express();

app.use(session({
  secret: process.env.SECRET_KEY || 'dev-secret-change-in-production',
  resave: false,
  saveUninitialized: false,
}));

app.use(passport.initialize());
app.use(passport.session());

passport.use('vouch', new OpenIDConnectStrategy({
  issuer: process.env.VOUCH_ISSUER || 'https://us.vouch.sh',
  authorizationURL: `${process.env.VOUCH_ISSUER || 'https://us.vouch.sh'}/oauth/authorize`,
  tokenURL: `${process.env.VOUCH_ISSUER || 'https://us.vouch.sh'}/oauth/token`,
  userInfoURL: `${process.env.VOUCH_ISSUER || 'https://us.vouch.sh'}/oauth/userinfo`,
  clientID: process.env.VOUCH_CLIENT_ID,
  clientSecret: process.env.VOUCH_CLIENT_SECRET,
  callbackURL: process.env.VOUCH_REDIRECT_URI || 'http://localhost:3000/auth/vouch/callback',
  scope: ['openid', 'email'],
}, (issuer, profile, context, idToken, accessToken, refreshToken, done) => {
  return done(null, {
    id: profile.id,
    email: profile.emails?.[0]?.value,
    hardwareVerified: idToken?.hardware_verified,
  });
}));

passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((user, done) => done(null, user));

app.get('/', (req, res) => {
  if (req.isAuthenticated()) {
    res.send(`
      <!DOCTYPE html>
      <html>
      <head><title>Vouch + Express</title></head>
      <body>
        <h1>Vouch OIDC + Express + Passport</h1>
        <p>Signed in as ${req.user.email}</p>
        ${req.user.hardwareVerified ? '<p><strong>Hardware Verified</strong></p>' : ''}
        <a href="/logout">Sign out</a>
      </body>
      </html>
    `);
  } else {
    res.send(`
      <!DOCTYPE html>
      <html>
      <head><title>Vouch + Express</title></head>
      <body>
        <h1>Vouch OIDC + Express + Passport</h1>
        <a href="/auth/vouch">Sign in with Vouch</a>
      </body>
      </html>
    `);
  }
});

app.get('/auth/vouch', passport.authenticate('vouch'));

app.get('/auth/vouch/callback',
  passport.authenticate('vouch', { failureRedirect: '/' }),
  (req, res) => res.redirect('/')
);

app.get('/logout', (req, res) => {
  req.logout(() => res.redirect('/'));
});

app.listen(3000, () => {
  console.log('Server running on http://localhost:3000');
});
