# Spring Boot + Spring Security OAuth2

Web Application (Confidential Client) using Vouch OIDC.

**Vouch application type:** Web (confidential client — issued a client secret and authorized for the authorization code grant).

## Environment Variables

| Variable | Description |
|---|---|
| `VOUCH_ISSUER` | OIDC issuer URI (default: `https://us.vouch.sh`) |
| `VOUCH_CLIENT_ID` | OAuth2 client ID |
| `VOUCH_CLIENT_SECRET` | OAuth2 client secret |
| `VOUCH_REDIRECT_URI` | Redirect URI (default: `http://localhost:3000/login/oauth2/code/vouch`) |

## Run with Docker

```bash
docker build -t vouch-spring-boot .

docker run -p 3000:3000 \
  -e VOUCH_ISSUER=https://us.vouch.sh \
  -e VOUCH_CLIENT_ID=your-client-id \
  -e VOUCH_CLIENT_SECRET=your-client-secret \
  vouch-spring-boot
```

## Callback URL

```
http://localhost:3000/login/oauth2/code/vouch
```

## Claims

The signed-in page shows `email`, `email_verified`, `sub`, `amr` and `acr` from the ID token, and `hardware_verified` from the access token. `hardware_verified` is not an ID token claim, so the access token (an ES256-signed RFC 9068 JWT) is verified against the issuer's JWKS -- `typ: at+jwt`, `iss`, `aud` = client ID, `exp` -- before it is read.

## Sign-out

Clearing only the local session would leave the user signed in at Vouch, so the next sign-in would complete silently. Sign-out therefore also ends the Vouch session with [OIDC RP-Initiated Logout](https://openid.net/specs/openid-connect-rpinitiated-1_0.html). Logout uses Spring Security's `OidcClientInitiatedLogoutSuccessHandler`, which redirects to the `end_session_endpoint` from discovery with the ID token as `id_token_hint`.

Vouch shows a confirmation page and only redirects back when `id_token_hint` verifies **and** `post_logout_redirect_uri` exactly matches a URI registered on the client. The post-logout redirect URI the app sends is the origin of `VOUCH_REDIRECT_URI` followed by `/`. Register it exactly, including the trailing slash:

```
http://localhost:3000/
```

Otherwise Vouch finishes on its own signed-out page. The access token is not revoked: Vouch revokes by user, so revocation would sign the user out of every application and device.
