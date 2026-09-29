using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

/// <summary>
/// Adds DPoP proofs (RFC 9449) to the OpenID Connect handler's backchannel requests.
/// </summary>
/// <remarks>
/// ASP.NET Core's OpenID Connect handler has no DPoP support, so this handler is installed
/// as its BackchannelHttpHandler. The key pair lives for the process: the confidential
/// client, not the browser, holds the token.
///
/// The token request (a POST) gets a proof. The UserInfo request, which the handler sends
/// with the Bearer scheme, is switched to the DPoP scheme with a proof bound to the token
/// by <c>ath</c>; Vouch rejects a DPoP-bound token presented as Bearer. Discovery and JWKS
/// fetches carry no token and are left alone.
///
/// Vouch's token endpoint always answers the first attempt with <c>use_dpop_nonce</c> and a
/// <c>DPoP-Nonce</c> header, so a 400 or 401 carrying that header is retried once with the
/// nonce, and the latest nonce is sent up front on later requests.
/// </remarks>
public sealed class DPoPHandler : DelegatingHandler
{
    private const string DPoPNonceHeader = "DPoP-Nonce";

    private readonly ECDsa _key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    private readonly JsonWebTokenHandler _tokenHandler = new() { SetDefaultTimesOnTokenCreation = false };
    private string? _nonce;

    public DPoPHandler(HttpMessageHandler innerHandler) : base(innerHandler)
    {
    }

    protected override async Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var accessToken = AccessToken(request.Headers.Authorization);
        if (accessToken is null && request.Method != HttpMethod.Post)
        {
            return await base.SendAsync(request, cancellationToken);
        }
        if (accessToken is not null)
        {
            request.Headers.Authorization = new AuthenticationHeaderValue("DPoP", accessToken);
        }

        SetProof(request, accessToken, _nonce);
        var response = await base.SendAsync(request, cancellationToken);
        if (!response.Headers.TryGetValues(DPoPNonceHeader, out var values))
        {
            return response;
        }
        var issuedNonce = values.First();
        _nonce = issuedNonce;

        if (response.StatusCode is not (HttpStatusCode.BadRequest or HttpStatusCode.Unauthorized))
        {
            return response;
        }
        response.Dispose();
        SetProof(request, accessToken, issuedNonce);
        return await base.SendAsync(request, cancellationToken);
    }

    private void SetProof(HttpRequestMessage request, string? accessToken, string? nonce)
    {
        request.Headers.Remove("DPoP");
        request.Headers.Add("DPoP", CreateProof(request, accessToken, nonce));
    }

    private string CreateProof(HttpRequestMessage request, string? accessToken, string? nonce)
    {
        var uri = request.RequestUri
            ?? throw new InvalidOperationException("DPoP proof needs a request URI");
        var claims = new Dictionary<string, object>
        {
            ["jti"] = Guid.NewGuid().ToString(),
            ["htm"] = request.Method.Method,
            // htu excludes the query and fragment (RFC 9449 section 4.2).
            ["htu"] = uri.GetLeftPart(UriPartial.Path),
            ["iat"] = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
        };
        if (nonce is not null)
        {
            claims["nonce"] = nonce;
        }
        if (accessToken is not null)
        {
            claims["ath"] = Base64UrlEncoder.Encode(SHA256.HashData(Encoding.ASCII.GetBytes(accessToken)));
        }

        // The public key only; ExportParameters(false) leaves out the private scalar.
        var publicKey = _key.ExportParameters(false);
        var jwk = new Dictionary<string, object>
        {
            ["kty"] = "EC",
            ["crv"] = "P-256",
            ["x"] = Base64UrlEncoder.Encode(publicKey.Q.X),
            ["y"] = Base64UrlEncoder.Encode(publicKey.Q.Y),
        };

        return _tokenHandler.CreateToken(new SecurityTokenDescriptor
        {
            TokenType = "dpop+jwt",
            Claims = claims,
            AdditionalHeaderClaims = new Dictionary<string, object> { ["jwk"] = jwk },
            SigningCredentials = new SigningCredentials(
                new ECDsaSecurityKey(_key), SecurityAlgorithms.EcdsaSha256),
        });
    }

    private static string? AccessToken(AuthenticationHeaderValue? authorization) =>
        authorization is { Scheme: var scheme, Parameter: { } token }
            && (scheme.Equals("Bearer", StringComparison.OrdinalIgnoreCase)
                || scheme.Equals("DPoP", StringComparison.OrdinalIgnoreCase))
            ? token
            : null;

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            _key.Dispose();
        }
        base.Dispose(disposing);
    }
}
