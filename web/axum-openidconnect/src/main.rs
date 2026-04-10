use axum::{
    extract::{Query, State},
    response::{Html, IntoResponse, Redirect},
    routing::get,
    Router,
};
use openidconnect::{
    core::{
        CoreAuthDisplay, CoreAuthPrompt, CoreErrorResponseType, CoreGenderClaim,
        CoreJsonWebKey, CoreJsonWebKeyType, CoreJsonWebKeyUse,
        CoreJweContentEncryptionAlgorithm, CoreJwsSigningAlgorithm, CoreProviderMetadata,
        CoreResponseType, CoreRevocableToken, CoreTokenType,
    },
    AdditionalClaims, AuthenticationFlow, AuthorizationCode, Client, ClientId,
    ClientSecret, CsrfToken, EmptyExtraTokenFields, IdTokenFields, IssuerUrl, Nonce,
    PkceCodeChallenge, PkceCodeVerifier, RedirectUrl, RevocationErrorResponseType, Scope,
    StandardErrorResponse, StandardTokenIntrospectionResponse, StandardTokenResponse,
    TokenResponse, reqwest::async_http_client,
};
use base64::engine::{general_purpose::URL_SAFE_NO_PAD, Engine};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::RwLock;
use tower_sessions::{MemoryStore, Session, SessionManagerLayer};

// Additional claims placeholder (hardware claims are read from the access token JWT).
#[derive(Clone, Debug, Deserialize, Serialize)]
struct VouchClaims {}

impl AdditionalClaims for VouchClaims {}

type VouchIdTokenFields = IdTokenFields<
    VouchClaims,
    EmptyExtraTokenFields,
    CoreGenderClaim,
    CoreJweContentEncryptionAlgorithm,
    CoreJwsSigningAlgorithm,
    CoreJsonWebKeyType,
>;

type VouchClient = Client<
    VouchClaims,
    CoreAuthDisplay,
    CoreGenderClaim,
    CoreJweContentEncryptionAlgorithm,
    CoreJwsSigningAlgorithm,
    CoreJsonWebKeyType,
    CoreJsonWebKeyUse,
    CoreJsonWebKey,
    CoreAuthPrompt,
    StandardErrorResponse<CoreErrorResponseType>,
    StandardTokenResponse<VouchIdTokenFields, CoreTokenType>,
    CoreTokenType,
    StandardTokenIntrospectionResponse<EmptyExtraTokenFields, CoreTokenType>,
    CoreRevocableToken,
    StandardErrorResponse<RevocationErrorResponseType>,
>;

#[derive(Clone)]
struct AppState {
    client: VouchClient,
    // In production, use a proper session store
    pkce_verifiers: Arc<RwLock<std::collections::HashMap<String, (PkceCodeVerifier, Nonce)>>>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let issuer_url = IssuerUrl::new(
        std::env::var("VOUCH_ISSUER").unwrap_or_else(|_| "https://us.vouch.sh".to_string()),
    )?;

    let provider_metadata =
        CoreProviderMetadata::discover_async(issuer_url, async_http_client).await?;

    let redirect_uri = std::env::var("VOUCH_REDIRECT_URI")
        .unwrap_or_else(|_| "http://localhost:3000/callback".to_string());

    let client = VouchClient::from_provider_metadata(
        provider_metadata,
        ClientId::new(std::env::var("VOUCH_CLIENT_ID").expect("VOUCH_CLIENT_ID must be set")),
        Some(ClientSecret::new(
            std::env::var("VOUCH_CLIENT_SECRET").expect("VOUCH_CLIENT_SECRET must be set"),
        )),
    )
    .set_redirect_uri(RedirectUrl::new(redirect_uri)?);

    let state = AppState {
        client,
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
        format!(
            "<p>Signed in as {email}</p>{hw}<a href=\"/logout\">Sign out</a>"
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
        .client
        .authorize_url(
            AuthenticationFlow::<CoreResponseType>::AuthorizationCode,
            CsrfToken::new_random,
            Nonce::new_random,
        )
        .add_scope(Scope::new("email".to_string()))
        .set_pkce_challenge(pkce_challenge)
        .url();

    state.pkce_verifiers.write().await.insert(
        csrf_token.secret().clone(),
        (pkce_verifier, nonce),
    );

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

    let token_response = match state
        .client
        .exchange_code(AuthorizationCode::new(params.code))
        .set_pkce_verifier(pkce_verifier)
        .request_async(async_http_client)
        .await
    {
        Ok(t) => t,
        Err(_) => return Redirect::to("/").into_response(),
    };

    let id_token = match token_response.id_token() {
        Some(t) => t,
        None => return Redirect::to("/").into_response(),
    };

    let claims = match id_token.claims(&state.client.id_token_verifier(), &nonce) {
        Ok(c) => c,
        Err(_) => return Redirect::to("/").into_response(),
    };

    let email = claims
        .email()
        .map(|e| e.as_str().to_string())
        .unwrap_or_default();

    // Hardware claims are in the access token JWT (RFC 9068), not the id_token.
    // Extract via serialization since the TokenResponse trait's access_token()
    // method is shadowed by a private field in StandardTokenResponse.
    let hardware_verified = serde_json::to_value(&token_response)
        .ok()
        .and_then(|v| v["access_token"].as_str().map(String::from))
        .and_then(|at| {
            at.split('.').nth(1).and_then(|p| {
                URL_SAFE_NO_PAD
                    .decode(p)
                    .ok()
                    .and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).ok())
                    .and_then(|v| v["hardware_verified"].as_bool())
            })
        })
        .unwrap_or(false);

    let user = serde_json::json!({
        "email": email,
        "hardware_verified": hardware_verified,
    });

    let _ = session.insert("user", user).await;

    Redirect::to("/").into_response()
}

async fn logout(session: Session) -> Redirect {
    let _ = session.remove::<serde_json::Value>("user").await;
    Redirect::to("/")
}
