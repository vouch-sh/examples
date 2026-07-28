use axum::{
    extract::{Query, State},
    response::{Html, IntoResponse, Redirect},
    routing::get,
    Router,
};
use jsonwebtoken::{decode, decode_header, jwk::JwkSet, DecodingKey, Validation};
use openidconnect::{
    core::{CoreClient, CoreProviderMetadata, CoreResponseType},
    AuthenticationFlow, AuthorizationCode, ClientId, ClientSecret, CsrfToken, EndpointMaybeSet,
    EndpointNotSet, EndpointSet, IssuerUrl, Nonce, OAuth2TokenResponse, PkceCodeChallenge,
    PkceCodeVerifier, RedirectUrl, Scope, TokenResponse,
};
use serde::Deserialize;
use std::sync::Arc;
use tokio::sync::RwLock;
use tower_sessions::{MemoryStore, Session, SessionManagerLayer};

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
    #[serde(default)]
    acr: Option<String>,
    #[serde(default)]
    amr: Vec<String>,
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
    let jwks: JwkSet = http_client
        .get(format!("{issuer}/oauth/jwks"))
        .send()
        .await?
        .json()
        .await?;
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
    client_id: String,
    // In production, use a proper session store
    pkce_verifiers: Arc<RwLock<std::collections::HashMap<String, (PkceCodeVerifier, Nonce)>>>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let http_client = reqwest::ClientBuilder::new()
        .redirect(reqwest::redirect::Policy::none())
        .build()?;

    let issuer =
        std::env::var("VOUCH_ISSUER").unwrap_or_else(|_| "https://us.vouch.sh".to_string());
    let issuer_url = IssuerUrl::new(issuer.clone())?;

    let provider_metadata = CoreProviderMetadata::discover_async(issuer_url, &http_client).await?;

    let redirect_uri = std::env::var("VOUCH_REDIRECT_URI")
        .unwrap_or_else(|_| "http://localhost:3000/callback".to_string());

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
        client_id,
        pkce_verifiers: Arc::new(RwLock::new(std::collections::HashMap::new())),
    };

    let session_store = MemoryStore::default();
    let session_layer = SessionManagerLayer::new(session_store);

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
        format!(
            "<p>Signed in as {email}</p>{hw}<p>acr: {acr}</p><p>amr: {amr}</p>\
             <a href=\"/logout\">Sign out</a>"
        )
    } else {
        "<a href=\"/login\">Sign in with Vouch</a>".to_string()
    };

    Html(format!(
        "<!DOCTYPE html><html><head><title>Vouch + Axum</title></head>\
         <body><h1>Vouch OIDC + Axum + openidconnect</h1>{content}</body></html>"
    ))
}

async fn login(State(state): State<AppState>) -> Redirect {
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

    state
        .pkce_verifiers
        .write()
        .await
        .insert(csrf_token.secret().clone(), (pkce_verifier, nonce));

    Redirect::to(auth_url.as_str())
}

#[derive(Deserialize)]
struct CallbackParams {
    code: String,
    state: String,
}

async fn callback(
    Query(params): Query<CallbackParams>,
    State(state): State<AppState>,
    session: Session,
) -> impl IntoResponse {
    let (pkce_verifier, nonce) = match state.pkce_verifiers.write().await.remove(&params.state) {
        Some(v) => v,
        None => return Redirect::to("/").into_response(),
    };

    let code_request = match state
        .oidc_client
        .exchange_code(AuthorizationCode::new(params.code))
    {
        Ok(req) => req,
        Err(_) => return Redirect::to("/").into_response(),
    };

    let token_response = match code_request
        .set_pkce_verifier(pkce_verifier)
        .request_async(&state.http_client)
        .await
    {
        Ok(t) => t,
        Err(_) => return Redirect::to("/").into_response(),
    };

    let id_token = match token_response.id_token() {
        Some(t) => t,
        None => return Redirect::to("/").into_response(),
    };

    let claims = match id_token.claims(&state.oidc_client.id_token_verifier(), &nonce) {
        Ok(c) => c,
        Err(_) => return Redirect::to("/").into_response(),
    };

    let email = claims
        .email()
        .map(|e| e.as_str().to_string())
        .unwrap_or_default();

    let at_claims = match verify_access_token(
        &state.http_client,
        &state.issuer,
        &state.client_id,
        token_response.access_token().secret(),
    )
    .await
    {
        Ok(at_claims) => at_claims,
        Err(err) => {
            return Html(format!(
                "<h1>Access token verification failed</h1><p>{err}</p>"
            ))
            .into_response()
        }
    };

    let user = serde_json::json!({
        "email": email,
        "hardware_verified": at_claims.hardware_verified,
        "acr": at_claims.acr,
        "amr": at_claims.amr,
    });

    let _ = session.insert("user", user).await;

    Redirect::to("/").into_response()
}

async fn logout(session: Session) -> Redirect {
    let _ = session.remove::<serde_json::Value>("user").await;
    Redirect::to("/")
}
