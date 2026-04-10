using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Http;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;

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
    options.PushedAuthorizationBehavior = PushedAuthorizationBehavior.Disable;
    options.ResponseMode = OpenIdConnectResponseMode.Query;
    options.Events = new Microsoft.AspNetCore.Authentication.OpenIdConnect.OpenIdConnectEvents
    {
        OnRedirectToIdentityProvider = context =>
        {
            context.ProtocolMessage.RedirectUri = redirectUri;
            return System.Threading.Tasks.Task.CompletedTask;
        },
    };
});

builder.Services.AddAuthorization();

var app = builder.Build();

app.UseAuthentication();
app.UseAuthorization();

// Hardware claims are in the access token JWT (RFC 9068), not the id_token.
static bool DecodeHardwareVerified(string? accessToken)
{
    if (string.IsNullOrEmpty(accessToken)) return false;
    var parts = accessToken.Split('.');
    if (parts.Length != 3) return false;
    try
    {
        var payload = parts[1].Replace('-', '+').Replace('_', '/');
        payload = payload.PadRight(payload.Length + (4 - payload.Length % 4) % 4, '=');
        var json = JsonDocument.Parse(Encoding.UTF8.GetString(Convert.FromBase64String(payload)));
        return json.RootElement.TryGetProperty("hardware_verified", out var hw) && hw.GetBoolean();
    }
    catch { return false; }
}

app.MapGet("/", async (HttpContext context) =>
{
    if (context.User.Identity?.IsAuthenticated == true)
    {
        var email = context.User.FindFirst("email")?.Value
            ?? context.User.FindFirst(System.Security.Claims.ClaimTypes.Email)?.Value
            ?? "unknown";
        var accessToken = await context.GetTokenAsync("access_token");
        var hwVerified = DecodeHardwareVerified(accessToken);
        var hwBadge = hwVerified ? "<p><strong>Hardware Verified</strong></p>" : "";

        return Results.Content(
            $"""
            <!DOCTYPE html>
            <html><head><title>Vouch + ASP.NET Core</title></head><body>
            <h1>Vouch OIDC + ASP.NET Core</h1>
            <p>Signed in as {email}</p>
            {hwBadge}
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

app.MapPost("/logout", async (HttpContext context) =>
{
    await context.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
    return Results.Redirect("/");
});

app.Run();
