use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::{Html, IntoResponse, Redirect, Response},
    routing::get,
    Router,
};
use jsonwebtoken::{decode, decode_header, jwk::JwkSet, DecodingKey, Validation};
use openidconnect::{
    core::{CoreClient, CoreIdToken, CoreResponseType},
    AuthenticationFlow, AuthorizationCode, ClientId, ClientSecret, CsrfToken, EndSessionUrl,
    EndpointMaybeSet, EndpointNotSet, EndpointSet, IssuerUrl, LogoutRequest, Nonce,
    OAuth2TokenResponse, PkceCodeChallenge, PkceCodeVerifier, PostLogoutRedirectUrl,
    ProviderMetadataWithLogout, RedirectUrl, Scope, TokenResponse,
};
use serde::{Deserialize, Serialize};
use tower_sessions::{cookie::SameSite, MemoryStore, Session, SessionManagerLayer};

type ConfiguredClient = CoreClient<
    EndpointSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointMaybeSet,
    EndpointMaybeSet,
>;

/// Claims read from a verified Vouch access token.
#[derive(Debug, Deserialize)]
struct AccessTokenClaims {
    #[serde(default)]
    hardware_verified: bool,
}

/// Verify a Vouch access token against the issuer's published JWKS.
///
/// hardware_verified is only in the access token, not the id_token. The access token is
/// an ES256-signed RFC 9068 JWT, so verify it rather than decoding the payload -- an
/// unverified decode trusts whatever bytes you were handed.
///
/// The JWKS is refetched per login to keep the example short. A real service should
/// cache it and only refetch when it encounters an unknown `kid`.
async fn verify_access_token(
    http_client: &reqwest::Client,
    issuer: &str,
    jwks_uri: &str,
    client_id: &str,
    token: &str,
) -> Result<AccessTokenClaims, Box<dyn std::error::Error>> {
    let header = decode_header(token)?;

    // RFC 9068 access tokens carry typ: at+jwt. Requiring it rejects id_tokens, which
    // are not bearer credentials.
    match header.typ.as_deref() {
        Some(typ) if typ.eq_ignore_ascii_case("at+jwt") => {}
        other => return Err(format!("unexpected token typ: {other:?}").into()),
    }

    let kid = header.kid.ok_or("access token has no kid")?;
    let jwks: JwkSet = http_client.get(jwks_uri).send().await?.json().await?;
    let jwk = jwks.find(&kid).ok_or("kid not published in JWKS")?;

    let mut validation = Validation::new(header.alg);
    // The audience is this client's own client_id, which is what Vouch issues when the
    // authorization request carries no RFC 8707 resource parameter.
    validation.set_audience(&[client_id]);
    validation.set_issuer(&[issuer]);

    let data = decode::<AccessTokenClaims>(token, &DecodingKey::from_jwk(jwk)?, &validation)?;
    Ok(data.claims)
}

#[derive(Clone)]
struct AppState {
    oidc_client: ConfiguredClient,
    http_client: reqwest::Client,
    issuer: String,
    // From discovery rather than assumed from the issuer's URL layout.
    jwks_uri: String,
    client_id: String,
    // None when the provider does not advertise end_session_endpoint.
    end_session_url: Option<EndSessionUrl>,
    post_logout_redirect_uri: PostLogoutRedirectUrl,
}

/// What /login keeps in the browser's session for /callback.
///
/// Holding it in the session rather than in a server-wide map keyed by state is what
/// makes the state check meaningful: the callback only succeeds in the browser that
/// started the sign-in, which is the login CSRF protection state exists for.
#[derive(Serialize, Deserialize)]
struct PendingLogin {
    csrf_token: CsrfToken,
    pkce_verifier: PkceCodeVerifier,
    nonce: Nonce,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let http_client = reqwest::ClientBuilder::new()
        .redirect(reqwest::redirect::Policy::none())
        .build()?;

    let issuer =
        std::env::var("VOUCH_ISSUER").unwrap_or_else(|_| "https://us.vouch.sh".to_string());
    let issuer_url = IssuerUrl::new(issuer.clone())?;

    // The "WithLogout" metadata type also parses end_session_endpoint (OIDC
    // RP-Initiated Logout 1.0), which the core metadata type ignores.
    let provider_metadata =
        ProviderMetadataWithLogout::discover_async(issuer_url, &http_client).await?;
    let jwks_uri = provider_metadata.jwks_uri().url().to_string();
    let end_session_url = provider_metadata
        .additional_metadata()
        .end_session_endpoint
        .clone();

    let redirect_uri = std::env::var("VOUCH_REDIRECT_URI")
        .unwrap_or_else(|_| "http://localhost:3000/callback".to_string());

    let post_logout_redirect_uri =
        PostLogoutRedirectUrl::from_url(reqwest::Url::parse(&redirect_uri)?.join("/")?);

    let client_id = std::env::var("VOUCH_CLIENT_ID").expect("VOUCH_CLIENT_ID must be set");

    let oidc_client = CoreClient::from_provider_metadata(
        provider_metadata,
        ClientId::new(client_id.clone()),
        Some(ClientSecret::new(
            std::env::var("VOUCH_CLIENT_SECRET").expect("VOUCH_CLIENT_SECRET must be set"),
        )),
    )
    .set_redirect_uri(RedirectUrl::new(redirect_uri)?);

    let state = AppState {
        oidc_client,
        http_client,
        issuer,
        jwks_uri,
        client_id,
        end_session_url,
        post_logout_redirect_uri,
    };

    let session_store = MemoryStore::default();
    // Lax rather than the default Strict: the callback arrives as a top-level
    // cross-site redirect from Vouch, and it needs the session that /login wrote.
    let session_layer = SessionManagerLayer::new(session_store).with_same_site(SameSite::Lax);

    let app = Router::new()
        .route("/", get(home))
        .route("/login", get(login))
        .route("/callback", get(callback))
        .route("/logout", get(logout))
        .layer(session_layer)
        .with_state(state);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await?;
    println!("Server running on http://localhost:3000");
    axum::serve(listener, app).await?;

    Ok(())
}

async fn home(session: Session) -> Html<String> {
    let user: Option<serde_json::Value> = session.get("user").await.unwrap_or(None);

    let content = if let Some(user) = user {
        let email = user["email"].as_str().unwrap_or("Unknown");
        let hw = if user["hardware_verified"].as_bool().unwrap_or(false) {
            "<p><strong>Hardware Verified</strong></p>"
        } else {
            ""
        };
        let email_verified = user["email_verified"].as_bool().unwrap_or(false);
        let sub = user["sub"].as_str().unwrap_or("N/A");
        let acr = user["acr"].as_str().unwrap_or("N/A");
        let amr = user["amr"]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            })
            .unwrap_or_default();
        let hardware_verified = user["hardware_verified"].as_bool().unwrap_or(false);
        format!(
            "<p>Signed in as {email}</p>{hw}<ul>\
             <li>email: {email}</li>\
             <li>email_verified: {email_verified}</li>\
             <li>sub: {sub}</li>\
             <li>amr: {amr}</li>\
             <li>acr: {acr}</li>\
             <li>hardware_verified: {hardware_verified}</li>\
             </ul><a href=\"/logout\">Sign out</a>"
        )
    } else {
        "<a href=\"/login\">Sign in with Vouch</a>".to_string()
    };

    Html(format!(
        "<!DOCTYPE html><html><head><title>Vouch + Axum</title></head>\
         <body><h1>Vouch OIDC + Axum + openidconnect</h1>{content}</body></html>"
    ))
}

async fn login(State(state): State<AppState>, session: Session) -> Response {
    let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();

    let (auth_url, csrf_token, nonce) = state
        .oidc_client
        .authorize_url(
            AuthenticationFlow::<CoreResponseType>::AuthorizationCode,
            CsrfToken::new_random,
            Nonce::new_random,
        )
        .add_scope(Scope::new("email".to_string()))
        .set_pkce_challenge(pkce_challenge)
        .url();

    let pending = PendingLogin {
        csrf_token,
        pkce_verifier,
        nonce,
    };
    if let Err(err) = session.insert("oidc_pending", pending).await {
        return error_page(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("Could not store the sign-in state: {err}"),
        );
    }

    Redirect::to(auth_url.as_str()).into_response()
}

#[derive(Deserialize)]
struct CallbackParams {
    code: Option<String>,
    state: Option<String>,
    // Set instead of `code` when Vouch ends the authorization with an error
    // (RFC 6749 section 4.1.2.1), for example when the user denies consent.
    error: Option<String>,
    error_description: Option<String>,
}

async fn callback(
    Query(params): Query<CallbackParams>,
    State(state): State<AppState>,
    session: Session,
) -> Response {
    match complete_login(params, &state, &session).await {
        Ok(()) => Redirect::to("/").into_response(),
        Err((status, message)) => error_page(status, &message),
    }
}

type CallbackError = (StatusCode, String);

fn server_error(context: &str, err: impl std::fmt::Display) -> CallbackError {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        format!("{context}: {err}"),
    )
}

async fn complete_login(
    params: CallbackParams,
    state: &AppState,
    session: &Session,
) -> Result<(), CallbackError> {
    if let Some(error) = params.error {
        let description = params.error_description.unwrap_or_default();
        return Err((
            StatusCode::BAD_REQUEST,
            format!("Vouch returned {error}: {description}"),
        ));
    }

    let pending: PendingLogin = session
        .remove("oidc_pending")
        .await
        .map_err(|err| server_error("Could not read the sign-in state", err))?
        .ok_or((
            StatusCode::BAD_REQUEST,
            "No sign-in is in progress in this browser".to_string(),
        ))?;
    if params.state.as_deref() != Some(pending.csrf_token.secret().as_str()) {
        return Err((StatusCode::BAD_REQUEST, "State mismatch".to_string()));
    }
    let code = params.code.ok_or((
        StatusCode::BAD_REQUEST,
        "Callback carried no authorization code".to_string(),
    ))?;

    let token_response = state
        .oidc_client
        .exchange_code(AuthorizationCode::new(code))
        .map_err(|err| server_error("Token endpoint is not configured", err))?
        .set_pkce_verifier(pending.pkce_verifier)
        .request_async(&state.http_client)
        .await
        .map_err(|err| server_error("Token exchange failed", err))?;

    let id_token = token_response.id_token().ok_or((
        StatusCode::INTERNAL_SERVER_ERROR,
        "Token response carried no ID token".to_string(),
    ))?;

    let claims = id_token
        .claims(&state.oidc_client.id_token_verifier(), &pending.nonce)
        .map_err(|err| server_error("ID token verification failed", err))?;

    let email = claims
        .email()
        .map(|e| e.as_str().to_string())
        .unwrap_or_default();

    let at_claims = verify_access_token(
        &state.http_client,
        &state.issuer,
        &state.jwks_uri,
        &state.client_id,
        token_response.access_token().secret(),
    )
    .await
    .map_err(|err| server_error("Access token verification failed", err))?;

    let user = serde_json::json!({
        "email": email,
        "email_verified": claims.email_verified().unwrap_or(false),
        "sub": claims.subject().as_str(),
        "acr": claims.auth_context_ref().map(|acr| acr.as_str()),
        "amr": claims
            .auth_method_refs()
            .map(|amr| amr.iter().map(|m| m.as_str()).collect::<Vec<_>>())
            .unwrap_or_default(),
        "hardware_verified": at_claims.hardware_verified,
    });

    session
        .insert("user", user)
        .await
        .map_err(|err| server_error("Could not store the session", err))?;
    // Kept for RP-initiated logout: Vouch only honours post_logout_redirect_uri when a
    // verified id_token_hint identifies the client.
    session
        .insert("id_token", id_token)
        .await
        .map_err(|err| server_error("Could not store the session", err))?;

    Ok(())
}

fn error_page(status: StatusCode, message: &str) -> Response {
    // The message can include Vouch's error_description, so escape it.
    let message = message
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;");
    (
        status,
        Html(format!(
            "<!DOCTYPE html><html><head><title>Vouch + Axum</title></head>\
             <body><h1>Sign-in failed</h1><p>{message}</p><a href=\"/\">Back</a></body></html>"
        )),
    )
        .into_response()
}

/// Sign out locally, then at Vouch (OIDC RP-Initiated Logout 1.0).
///
/// Clearing only the local session leaves the user signed in at Vouch, so the next
/// sign-in would complete silently. Vouch shows a confirmation page and redirects back
/// only when id_token_hint verifies and post_logout_redirect_uri is registered.
async fn logout(State(state): State<AppState>, session: Session) -> Redirect {
    let _ = session.remove::<serde_json::Value>("user").await;
    let id_token = session
        .remove::<CoreIdToken>("id_token")
        .await
        .unwrap_or(None);

    match (state.end_session_url, id_token) {
        (Some(end_session_url), Some(id_token)) => {
            let url = LogoutRequest::from(end_session_url)
                .set_id_token_hint(&id_token)
                .set_post_logout_redirect_uri(state.post_logout_redirect_uri)
                .set_client_id(ClientId::new(state.client_id))
                .http_get_url();
            Redirect::to(url.as_str())
        }
        _ => Redirect::to("/"),
    }
}
