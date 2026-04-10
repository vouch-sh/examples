use std::env;
use std::sync::Arc;

use http_body_util::Full;
use hyper::body::Bytes;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder as ServerBuilder;
use jsonwebtoken::{decode, DecodingKey, Validation};
use serde::{Deserialize, Serialize};
use spiffe::X509Source;
use spiffe_rustls::{authorizer, mtls_server};
use spiffe_rustls_tokio::TlsAcceptor;
use tokio::net::TcpListener;

#[derive(Debug, Deserialize, Serialize)]
struct VouchClaims {
    email: Option<String>,
    sub: Option<String>,
    hardware_verified: Option<bool>,
    hardware_aaguid: Option<String>,
}

#[derive(Clone)]
struct AppState {
    vouch_issuer: String,
    jwks: Arc<jsonwebtoken::jwk::JwkSet>,
    server_spiffe_id: String,
}

async fn handle(
    req: Request<hyper::body::Incoming>,
    peer_spiffe_id: String,
    state: AppState,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    let (status, content_type, body) = match req.uri().path() {
        "/" => (
            StatusCode::OK,
            "text/html",
            format!(
                r#"<!DOCTYPE html>
<html><head><title>SPIFFE mTLS + Vouch</title></head><body>
<h1>SPIFFE mTLS + Vouch OIDC</h1>
<p><strong>Server SPIFFE ID:</strong> {}</p>
<p><strong>Peer SPIFFE ID:</strong> {}</p>
<p>Send a request to <code>/whoami</code> with an <code>Authorization: Bearer &lt;vouch-jwt&gt;</code> header.</p>
</body></html>"#,
                state.server_spiffe_id, peer_spiffe_id
            ),
        ),
        "/whoami" => {
            let auth = req
                .headers()
                .get("authorization")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("");

            if !auth.starts_with("Bearer ") {
                (
                    StatusCode::UNAUTHORIZED,
                    "application/json",
                    r#"{"error":"Authorization: Bearer <vouch-jwt> header required"}"#.to_string(),
                )
            } else {
                let token = &auth[7..];
                match verify_vouch_jwt(token, &state) {
                    Ok(claims) => {
                        let resp = serde_json::json!({
                            "workload_identity": {
                                "server_spiffe_id": state.server_spiffe_id,
                                "peer_spiffe_id": peer_spiffe_id,
                            },
                            "user_identity": {
                                "email": claims.email,
                                "sub": claims.sub,
                                "hardware_verified": claims.hardware_verified,
                                "hardware_aaguid": claims.hardware_aaguid,
                            },
                        });
                        (StatusCode::OK, "application/json", resp.to_string())
                    }
                    Err(e) => (
                        StatusCode::UNAUTHORIZED,
                        "application/json",
                        format!(r#"{{"error":"token verification failed: {e}"}}"#),
                    ),
                }
            }
        }
        _ => (
            StatusCode::NOT_FOUND,
            "text/plain",
            "Not Found".to_string(),
        ),
    };

    Ok(Response::builder()
        .status(status)
        .header("content-type", content_type)
        .body(Full::new(Bytes::from(body)))
        .unwrap())
}

fn verify_vouch_jwt(
    token: &str,
    state: &AppState,
) -> Result<VouchClaims, Box<dyn std::error::Error>> {
    let header = jsonwebtoken::decode_header(token)?;
    let kid = header.kid.ok_or("JWT missing kid header")?;
    let jwk = state
        .jwks
        .find(&kid)
        .ok_or_else(|| format!("key {kid} not found in JWKS"))?;
    let key = DecodingKey::from_jwk(jwk)?;

    let mut validation = Validation::new(header.alg);
    validation.set_issuer(&[&state.vouch_issuer]);
    validation.validate_aud = false;

    let data = decode::<VouchClaims>(token, &key, &validation)?;
    Ok(data.claims)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let vouch_issuer =
        env::var("VOUCH_ISSUER").unwrap_or_else(|_| "https://us.vouch.sh".to_string());
    let _client_id = env::var("VOUCH_CLIENT_ID").expect("VOUCH_CLIENT_ID is required");

    // Fetch Vouch JWKS for JWT verification
    let jwks_url = format!("{vouch_issuer}/oauth/jwks");
    let jwks: jsonwebtoken::jwk::JwkSet = reqwest::get(&jwks_url).await?.json().await?;
    println!("Loaded Vouch JWKS from {jwks_url}");

    // Connect to SPIFFE Workload API for X.509-SVIDs
    let source = X509Source::new().await?;
    let svid = source.svid()?;
    let server_spiffe_id = svid.spiffe_id().to_string();
    println!("Server SPIFFE ID: {server_spiffe_id}");

    // Build mTLS server config from SPIFFE X.509-SVIDs
    let server_config = mtls_server(source)
        .authorize(authorizer::any())
        .build()?;

    let state = AppState {
        vouch_issuer,
        jwks: Arc::new(jwks),
        server_spiffe_id,
    };

    let acceptor = TlsAcceptor::new(Arc::new(server_config));
    let listener = TcpListener::bind("0.0.0.0:3000").await?;
    println!("Server running on https://localhost:3000 (SPIFFE mTLS)");

    loop {
        let (stream, _) = listener.accept().await?;
        let acceptor = acceptor.clone();
        let state = state.clone();

        tokio::spawn(async move {
            let (tls_stream, peer_identity) = match acceptor.accept(stream).await {
                Ok(result) => result,
                Err(e) => {
                    eprintln!("TLS handshake failed: {e}");
                    return;
                }
            };

            let peer_spiffe_id = peer_identity
                .spiffe_id()
                .map(|id| id.to_string())
                .unwrap_or_else(|| "unknown".to_string());

            let io = TokioIo::new(tls_stream);
            let service = service_fn(move |req| {
                let peer_spiffe_id = peer_spiffe_id.clone();
                let state = state.clone();
                async move { handle(req, peer_spiffe_id, state).await }
            });

            if let Err(e) = ServerBuilder::new(TokioExecutor::new())
                .serve_connection(io, service)
                .await
            {
                eprintln!("HTTP error: {e}");
            }
        });
    }
}
