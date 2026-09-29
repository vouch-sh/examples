using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Http;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;

var builder = WebApplication.CreateBuilder(args);

var vouchIssuer = Environment.GetEnvironmentVariable("VOUCH_ISSUER") ?? "https://us.vouch.sh";
var clientId = Environment.GetEnvironmentVariable("VOUCH_CLIENT_ID")
    ?? throw new InvalidOperationException("VOUCH_CLIENT_ID is required");
var clientSecret = Environment.GetEnvironmentVariable("VOUCH_CLIENT_SECRET")
    ?? throw new InvalidOperationException("VOUCH_CLIENT_SECRET is required");
var redirectUri = Environment.GetEnvironmentVariable("VOUCH_REDIRECT_URI") ?? "http://localhost:3000/callback";

builder.Services.AddAuthentication(options =>
{
    options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
})
.AddCookie()
.AddOpenIdConnect(options =>
{
    options.Authority = vouchIssuer;
    options.ClientId = clientId;
    options.ClientSecret = clientSecret;
    options.ResponseType = OpenIdConnectResponseType.Code;
    options.UsePkce = true;
    options.Scope.Clear();
    options.Scope.Add("openid");
    options.Scope.Add("email");
    options.SaveTokens = true;
    options.GetClaimsFromUserInfoEndpoint = true;
    options.CallbackPath = new PathString(new Uri(redirectUri).AbsolutePath);
    // Vouch supports PAR (RFC 9126) and .NET would use it automatically, but PAR
    // changes the authentication model: Vouch requires a fresh FIDO2 assertion for
    // every PAR authorization, per FAPI 2.0 Section 5.3.2.2 Note 3. An existing
    // browser session no longer satisfies the request, so the user must touch their
    // security key on each sign-in.
    //
    // That is the right trade for a high-assurance app and the wrong one for a
    // minimal example, so it is off here. Switch to `Require` to opt in.
    options.PushedAuthorizationBehavior = PushedAuthorizationBehavior.Disable;
    options.ResponseMode = OpenIdConnectResponseMode.Query;
    options.Events = new Microsoft.AspNetCore.Authentication.OpenIdConnect.OpenIdConnectEvents
    {
        OnRedirectToIdentityProvider = context =>
        {
            context.ProtocolMessage.RedirectUri = redirectUri;
            return System.Threading.Tasks.Task.CompletedTask;
        },
        // SignOutAsync on this scheme performs RP-initiated logout: it redirects to
        // the end_session_endpoint from discovery with the saved ID token as
        // id_token_hint. Its default post_logout_redirect_uri is
        // /signout-callback-oidc; send the user straight back to `/` instead. Vouch
        // only redirects there when the hint verifies and the URI exactly matches
        // one registered on the client.
        OnRedirectToIdentityProviderForSignOut = context =>
        {
            context.ProtocolMessage.PostLogoutRedirectUri = new Uri(new Uri(redirectUri), "/").ToString();
            return System.Threading.Tasks.Task.CompletedTask;
        },
    };
});

builder.Services.AddAuthorization();

var app = builder.Build();

app.UseAuthentication();
app.UseAuthorization();

// hardware_verified is only in the access token, not the id_token. The access token is
// an ES256-signed RFC 9068 JWT, so verify it against the issuer's published JWKS rather
// than decoding the payload -- an unverified decode trusts whatever bytes you were
// handed. The configuration manager caches and refreshes the signing keys.
var configManager = new ConfigurationManager<OpenIdConnectConfiguration>(
    $"{vouchIssuer}/.well-known/openid-configuration",
    new OpenIdConnectConfigurationRetriever());

var tokenHandler = new JsonWebTokenHandler();

async Task<JsonWebToken?> VerifyAccessTokenAsync(string? accessToken)
{
    if (string.IsNullOrEmpty(accessToken)) return null;

    var oidcConfig = await configManager.GetConfigurationAsync();
    var result = await tokenHandler.ValidateTokenAsync(accessToken, new TokenValidationParameters
    {
        ValidIssuer = vouchIssuer,
        // The audience is this client's own client_id, which is what Vouch issues when
        // the authorization request carries no RFC 8707 resource parameter.
        ValidAudience = clientId,
        IssuerSigningKeys = oidcConfig.SigningKeys,
        // RFC 9068 access tokens carry typ: at+jwt. Requiring it rejects id_tokens,
        // which are not bearer credentials.
        ValidTypes = new[] { "at+jwt" },
    });

    return result.IsValid ? (JsonWebToken)result.SecurityToken : null;
}

app.MapGet("/", async (HttpContext context) =>
{
    if (context.User.Identity?.IsAuthenticated == true)
    {
        var email = context.User.FindFirst("email")?.Value
            ?? context.User.FindFirst(System.Security.Claims.ClaimTypes.Email)?.Value
            ?? "unknown";
        // The handler validated the ID token at sign-in and SaveTokens kept it in the
        // protected auth cookie. Reading claims from it directly avoids the handler's
        // inbound claim mapping, which renames sub and amr and drops acr.
        var idToken = new JsonWebToken(await context.GetTokenAsync("id_token"));
        var emailVerified = idToken.TryGetPayloadValue<bool>("email_verified", out var ev) && ev;
        var amr = string.Join(", ", idToken.Claims.Where(c => c.Type == "amr").Select(c => c.Value));
        var acr = idToken.TryGetPayloadValue<string>("acr", out var acrValue) ? acrValue : "N/A";

        var accessToken = await context.GetTokenAsync("access_token");
        var verified = await VerifyAccessTokenAsync(accessToken);
        var hwVerified = verified is not null
            && verified.TryGetPayloadValue<bool>("hardware_verified", out var hw) && hw;
        var hwBadge = hwVerified ? "<p><strong>Hardware Verified</strong></p>" : "";

        return Results.Content(
            $"""
            <!DOCTYPE html>
            <html><head><title>Vouch + ASP.NET Core</title></head><body>
            <h1>Vouch OIDC + ASP.NET Core</h1>
            <p>Signed in as {email}</p>
            {hwBadge}
            <ul>
            <li>email: {email}</li>
            <li>email_verified: {emailVerified}</li>
            <li>sub: {idToken.Subject}</li>
            <li>amr: {(amr == "" ? "N/A" : amr)}</li>
            <li>acr: {acr}</li>
            <li>hardware_verified: {hwVerified}</li>
            </ul>
            <form method="post" action="/logout"><button type="submit">Sign out</button></form>
            </body></html>
            """,
            "text/html");
    }

    return Results.Content(
        """
        <!DOCTYPE html>
        <html><head><title>Vouch + ASP.NET Core</title></head><body>
        <h1>Vouch OIDC + ASP.NET Core</h1>
        <a href="/login">Sign in with Vouch</a>
        </body></html>
        """,
        "text/html");
});

app.MapGet("/login", () =>
    Results.Challenge(new AuthenticationProperties { RedirectUri = "/" },
        [OpenIdConnectDefaults.AuthenticationScheme]));

// Clearing only the local cookie leaves the user signed in at Vouch, so the next
// sign-in would complete silently. Signing out of the OpenID Connect scheme as well
// hands off to Vouch's end_session endpoint (see OnRedirectToIdentityProviderForSignOut).
app.MapPost("/logout", () =>
    Results.SignOut(new AuthenticationProperties { RedirectUri = "/" },
        [CookieAuthenticationDefaults.AuthenticationScheme, OpenIdConnectDefaults.AuthenticationScheme]));

app.Run();
