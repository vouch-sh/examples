/**
 * Configuration for all example applications.
 * Each entry describes one example with its Docker build path,
 * app type, login/logout selectors, and callback path.
 */

/** @type {Array<{ name: string, dir: string, type: "web"|"spa"|"native"|"mcp"|"a2a", loginSelector: string, logoutSelector: string, callbackPath: string, logoutMethod?: string }>} */
const WEB_EXAMPLES = [
  {
    name: "express-openid",
    dir: "web/express-openid",
    type: "web",
    loginSelector: 'a[href="/auth/vouch"]',
    logoutSelector: 'a[href="/logout"]',
    callbackPath: "/auth/vouch/callback",
    logoutMethod: "GET",
  },
  {
    name: "nextjs-nextauth",
    dir: "web/nextjs-nextauth",
    type: "web",
    loginSelector: 'button:has-text("Sign in with Vouch")',
    logoutSelector: 'button:has-text("Sign out")',
    callbackPath: "/api/auth/callback/vouch",
    logoutMethod: "signOut()",
    // NextAuth constructs callback URL from NEXTAUTH_URL, not VOUCH_REDIRECT_URI
    extraEnv: (baseUrl) => ({
      NEXTAUTH_URL: baseUrl,
      NEXTAUTH_SECRET: "test-secret-for-integration-tests",
    }),
  },
  {
    name: "django-allauth",
    dir: "web/django-allauth",
    type: "web",
    loginSelector: 'a:has-text("Sign in with Vouch")',
    logoutSelector: 'form[action*="logout"] button',
    callbackPath: "/accounts/oidc/vouch/login/callback/",
    logoutMethod: "POST",
    // django-allauth shows a "Sign In Via Vouch" confirmation page before redirecting
    preAuthorizeSelector: 'button:has-text("Continue")',
  },
  {
    name: "fastapi-authlib",
    dir: "web/fastapi-authlib",
    type: "web",
    loginSelector: 'a[href="/login"]',
    logoutSelector: 'a[href="/logout"]',
    callbackPath: "/callback",
    logoutMethod: "GET",
  },
  {
    name: "flask-authlib",
    dir: "web/flask-authlib",
    type: "web",
    loginSelector: 'a[href="/login"]',
    logoutSelector: 'a[href="/logout"]',
    callbackPath: "/callback",
    logoutMethod: "GET",
  },
  {
    name: "laravel-socialite",
    dir: "web/laravel-socialite",
    type: "web",
    loginSelector: 'a[href="/auth/redirect"]',
    logoutSelector: 'form[action="/logout"] button',
    callbackPath: "/auth/callback",
    logoutMethod: "POST",
  },
  {
    name: "rails-omniauth",
    dir: "web/rails-omniauth",
    type: "web",
    loginSelector: 'form[action="/auth/vouch"] button',
    logoutSelector: 'form button:has-text("Sign out")',
    callbackPath: "/auth/vouch/callback",
    logoutMethod: "DELETE",
  },
  {
    name: "spring-boot",
    dir: "web/spring-boot",
    type: "web",
    loginSelector: 'a[href="/oauth2/authorization/vouch"]',
    logoutSelector: 'form[action*="logout"] button',
    callbackPath: "/login/oauth2/code/vouch",
    logoutMethod: "POST",
  },
  {
    name: "go-oidc",
    dir: "web/go-oidc",
    type: "web",
    loginSelector: 'a[href="/login"]',
    logoutSelector: 'a[href="/logout"]',
    callbackPath: "/callback",
    logoutMethod: "GET",
  },
  {
    name: "axum-openidconnect",
    dir: "web/axum-openidconnect",
    type: "web",
    loginSelector: 'a[href="/login"]',
    logoutSelector: 'a[href="/logout"]',
    callbackPath: "/callback",
    logoutMethod: "GET",
  },
  {
    name: "aspnet-core",
    dir: "web/aspnet-core",
    type: "web",
    loginSelector: 'a[href="/login"]',
    logoutSelector: 'form[action="/logout"] button',
    callbackPath: "/callback",
    logoutMethod: "POST",
  },
];

/** @type {Array<{ name: string, dir: string, type: "spa", loginSelector: string, logoutSelector: string, logoutMethod: string }>} */
const SPA_EXAMPLES = [
  {
    name: "react",
    dir: "spa/react",
    type: "spa",
    loginSelector: 'button:has-text("Sign in with Vouch")',
    logoutSelector: 'button:has-text("Sign out")',
    logoutMethod: "removeUser()",
  },
  {
    name: "vue",
    dir: "spa/vue",
    type: "spa",
    loginSelector: 'button:has-text("Sign in with Vouch")',
    logoutSelector: 'button:has-text("Sign out")',
    logoutMethod: "signoutRedirect()",
  },
  {
    name: "angular",
    dir: "spa/angular",
    type: "spa",
    loginSelector: 'button:has-text("Sign in with Vouch")',
    logoutSelector: 'button:has-text("Sign out")',
    logoutMethod: "logoff()",
  },
  {
    name: "sveltekit",
    dir: "spa/sveltekit",
    type: "spa",
    loginSelector: 'button:has-text("Sign in with Vouch")',
    logoutSelector: 'button:has-text("Sign out")',
    logoutMethod: "signoutRedirect()",
  },
  {
    name: "vanilla-js",
    dir: "spa/vanilla-js",
    type: "spa",
    loginSelector: "button#login-btn",
    logoutSelector: "button#logout-btn",
    logoutMethod: "signoutRedirect()",
  },
];

/** @type {Array<{ name: string, dir: string, type: "native", stdoutMarkers: string[] }>} */
const NATIVE_EXAMPLES = [
  {
    name: "native-node",
    dir: "native/node",
    type: "native",
    stdoutMarkers: [
      "To sign in, visit:",
      "Enter code:",
      "Authenticated!",
      "Email:",
    ],
  },
  {
    name: "native-python",
    dir: "native/python",
    type: "native",
    stdoutMarkers: [
      "To sign in, visit:",
      "Enter code:",
      "Authenticated!",
      "Email:",
    ],
  },
  {
    name: "native-rust",
    dir: "native/rust",
    type: "native",
    stdoutMarkers: [
      "To sign in, visit:",
      "Enter code:",
      "Authenticated!",
      "Email:",
    ],
  },
];

/** @type {Array<{ name: string, dir: string, type: "mcp" }>} */
const MCP_EXAMPLES = [
  {
    name: "mcp-remote-server-ts",
    dir: "mcp/remote-server-ts",
    type: "mcp",
  },
  {
    name: "mcp-remote-server-py",
    dir: "mcp/remote-server-py",
    type: "mcp",
  },
];

/** @type {Array<{ name: string, dir: string, type: "a2a" }>} */
const A2A_EXAMPLES = [
  {
    name: "a2a-python-agent",
    dir: "a2a/python-agent",
    type: "a2a",
  },
];

module.exports = {
  WEB_EXAMPLES,
  SPA_EXAMPLES,
  NATIVE_EXAMPLES,
  MCP_EXAMPLES,
  A2A_EXAMPLES,
};
