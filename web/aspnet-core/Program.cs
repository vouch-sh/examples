using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;

var builder = WebApplication.CreateBuilder(args);

var vouchIssuer = Environment.GetEnvironmentVariable("VOUCH_ISSUER")
    ?? throw new InvalidOperationException("VOUCH_ISSUER is required");
var clientId = Environment.GetEnvironmentVariable("VOUCH_CLIENT_ID")
    ?? throw new InvalidOperationException("VOUCH_CLIENT_ID is required");
var clientSecret = Environment.GetEnvironmentVariable("VOUCH_CLIENT_SECRET")
    ?? throw new InvalidOperationException("VOUCH_CLIENT_SECRET is required");

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
    options.Scope.Clear();
    options.Scope.Add("openid");
    options.Scope.Add("email");
    options.SaveTokens = true;
    options.GetClaimsFromUserInfoEndpoint = true;
    options.CallbackPath = "/callback";

    options.ClaimActions.MapJsonKey("hardware_verified", "hardware_verified");
    options.ClaimActions.MapJsonKey("hardware_aaguid", "hardware_aaguid");
});

var app = builder.Build();

app.UseAuthentication();
app.UseAuthorization();

app.MapGet("/", (HttpContext context) =>
{
    if (context.User.Identity?.IsAuthenticated == true)
    {
        var email = context.User.FindFirst("email")?.Value
            ?? context.User.FindFirst(System.Security.Claims.ClaimTypes.Email)?.Value
            ?? "unknown";
        var hwVerified = context.User.FindFirst("hardware_verified")?.Value == "true"
            || context.User.FindFirst("hardware_verified")?.Value == "True";
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
