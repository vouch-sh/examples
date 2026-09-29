# ASP.NET Core + OpenID Connect

**Integration type:** Web Application (Confidential Client)

Uses `Microsoft.AspNetCore.Authentication.OpenIdConnect` with OIDC discovery.

**Vouch application type:** Web (confidential client — issued a client secret and authorized for the authorization code grant).

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `VOUCH_ISSUER` | No | Vouch issuer URL (default: `https://us.vouch.sh`) |
| `VOUCH_CLIENT_ID` | Yes | OAuth client ID |
| `VOUCH_CLIENT_SECRET` | Yes | OAuth client secret |
| `VOUCH_REDIRECT_URI` | No | Callback URL (default: `http://localhost:3000/callback`) |

## Run

```bash
docker build -t vouch-aspnet .
docker run -p 3000:3000 \
  -e VOUCH_ISSUER=https://us.vouch.sh \
  -e VOUCH_CLIENT_ID=your-client-id \
  -e VOUCH_CLIENT_SECRET=your-client-secret \
  -e VOUCH_REDIRECT_URI=http://localhost:3000/callback \
  vouch-aspnet
```

## Callback URL

```
http://localhost:3000/callback
```

## Claims

The signed-in page shows `email`, `email_verified`, `sub`, `amr` and `acr` from the ID token, and `hardware_verified` and `cnf.jkt` from the access token. `hardware_verified` is not an ID token claim, so the access token (an ES256-signed RFC 9068 JWT) is verified against the issuer's JWKS -- `typ: at+jwt`, `iss`, `aud` = client ID, `exp` -- before it is read.

## DPoP

Access tokens are sender-constrained with [DPoP (RFC 9449)](https://www.rfc-editor.org/rfc/rfc9449). ASP.NET Core's OpenID Connect handler has no DPoP support, so `DPoPHandler.cs` is installed as its `BackchannelHttpHandler`. It holds an ES256 key pair generated at startup:

- Token request: adds a DPoP proof. Vouch always answers the first attempt with `use_dpop_nonce` and a `DPoP-Nonce` header, so the handler retries once with that nonce.
- UserInfo request (`GetClaimsFromUserInfoEndpoint`): switches the `Authorization` scheme from `Bearer` to `DPoP` and binds the proof to the token with `ath`. Vouch rejects a DPoP-bound token presented as `Bearer`.
- Discovery and JWKS fetches carry no token and are sent unchanged.

The access token carries `cnf.jkt`, the thumbprint of that key, which the signed-in page shows.

## Sign-out

Clearing only the local session would leave the user signed in at Vouch, so the next sign-in would complete silently. Sign-out therefore also ends the Vouch session with [OIDC RP-Initiated Logout](https://openid.net/specs/openid-connect-rpinitiated-1_0.html). The `/logout` endpoint signs out of both the cookie and OpenID Connect schemes. The OpenID Connect handler redirects to the `end_session_endpoint` from discovery with the saved ID token (`SaveTokens`) as `id_token_hint`; `OnRedirectToIdentityProviderForSignOut` sets `post_logout_redirect_uri` to `/`.

Vouch shows a confirmation page and only redirects back when `id_token_hint` verifies **and** `post_logout_redirect_uri` exactly matches a URI registered on the client. The post-logout redirect URI the app sends is the origin of `VOUCH_REDIRECT_URI` followed by `/`. Register it exactly, including the trailing slash:

```
http://localhost:3000/
```

Otherwise Vouch finishes on its own signed-out page. The access token is not revoked: Vouch revokes by user, so revocation would sign the user out of every application and device.
