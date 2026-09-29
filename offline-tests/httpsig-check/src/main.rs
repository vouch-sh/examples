//! Replay requests signed by the examples' Python code through the exact
//! RFC 9421 middleware vouch-server mounts on /v1/credentials/*
//! (`vouch_httpsig::middleware::require_signature`), with a key resolver that
//! maps the registered JWK's kid to an `EcdsaP256Verifier` the same way
//! `OAuthClientKeyResolver` does (uncompressed SEC1 point from x/y).

use std::collections::HashSet;
use std::sync::{Arc, Mutex};

use axum::{Router, body::Body, routing::get, routing::post};
use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use http::{Request, StatusCode};
use tower::ServiceExt;
use vouch_httpsig::algorithm::VerifyingAlgorithm;
use vouch_httpsig::algorithm::ecdsa_p256::EcdsaP256Verifier;
use vouch_httpsig::middleware::{KeyResolver, NonceValidation, require_signature};

struct Resolver {
    kid: String,
    point: Vec<u8>,
    nonces: Mutex<HashSet<String>>,
}

impl KeyResolver for Resolver {
    fn resolve(
        &self,
        keyid: &str,
        _headers: &http::HeaderMap,
    ) -> impl std::future::Future<Output = Option<Arc<dyn VerifyingAlgorithm>>> + Send + '_ {
        let found = (keyid == self.kid)
            .then(|| Arc::new(EcdsaP256Verifier::new(&self.point)) as Arc<dyn VerifyingAlgorithm>);
        async move { found }
    }

    fn validate_nonce(
        &self,
        nonce: &str,
    ) -> impl std::future::Future<Output = NonceValidation> + Send + '_ {
        let ok = self.nonces.lock().unwrap().remove(nonce);
        async move {
            if ok {
                NonceValidation::Valid
            } else {
                NonceValidation::Invalid
            }
        }
    }
}

async fn ok() -> &'static str {
    "ok"
}

#[tokio::main]
async fn main() {
    let path = std::env::args()
        .nth(1)
        .expect("usage: httpsig-check <vectors.json>");
    let doc: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let jwk = &doc["jwk"];
    let mut point = vec![0x04u8];
    point.extend(URL_SAFE_NO_PAD.decode(jwk["x"].as_str().unwrap()).unwrap());
    point.extend(URL_SAFE_NO_PAD.decode(jwk["y"].as_str().unwrap()).unwrap());
    let resolver = Arc::new(Resolver {
        kid: jwk["kid"].as_str().unwrap().to_string(),
        point,
        nonces: Mutex::new(
            doc["nonces"]
                .as_array()
                .map(|a| a.iter().map(|n| n.as_str().unwrap().to_string()).collect())
                .unwrap_or_else(|| HashSet::from(["server-issued-nonce-1".to_string()])),
        ),
    });

    // Same routes and methods as build_credential_routes in vouch-server.
    let router = Router::new()
        .route("/v1/credentials/ssh", post(ok))
        .route("/v1/credentials/aws/token", get(ok))
        .route("/v1/credentials/github/token", post(ok))
        .layer(axum::middleware::from_fn_with_state(
            resolver,
            require_signature::<Resolver>,
        ));

    let mut failures = 0;
    for case in doc["cases"].as_array().unwrap() {
        // Origin-form target plus Host, as an HTTP/1.1 server receives it.
        let mut builder = Request::builder()
            .method(case["method"].as_str().unwrap())
            .uri(case["target"].as_str().unwrap())
            .header("host", case["host"].as_str().unwrap());
        for (name, value) in case["headers"].as_object().unwrap() {
            builder = builder.header(name.as_str(), value.as_str().unwrap());
        }
        let body = STANDARD.decode(case["body_b64"].as_str().unwrap()).unwrap();
        if !body.is_empty() {
            builder = builder.header("content-length", body.len());
        }
        let req = builder.body(Body::from(body)).unwrap();
        let status = router.clone().oneshot(req).await.unwrap().status();
        let expected = StatusCode::from_u16(case["expect"].as_u64().unwrap() as u16).unwrap();
        let verdict = if status == expected { "PASS" } else { "FAIL" };
        if status != expected {
            failures += 1;
        }
        println!(
            "{verdict} {:<45} got {} expected {}",
            case["name"].as_str().unwrap(),
            status.as_u16(),
            expected.as_u16()
        );
    }
    if failures > 0 {
        eprintln!("{failures} case(s) failed");
        std::process::exit(1);
    }
    println!("all cases behaved as expected");
}
