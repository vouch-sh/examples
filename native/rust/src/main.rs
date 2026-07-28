use jsonwebtoken::{decode, decode_header, jwk::JwkSet, DecodingKey, Validation};
use reqwest::Client;
use serde::Deserialize;
use std::time::Duration;

#[derive(Deserialize)]
struct DeviceResponse {
    device_code: String,
    user_code: String,
    verification_uri: String,
    #[allow(dead_code)]
    expires_in: u64,
    interval: Option<u64>,
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
}

#[derive(Deserialize)]
struct ErrorResponse {
    error: String,
}

#[derive(Deserialize)]
struct UserInfoResponse {
    email: Option<String>,
}

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
/// agent that acts on an unverified claim is acting on whatever it was handed.
async fn verify_access_token(
    client: &Client,
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
    let jwks: JwkSet = client
        .get(format!("{issuer}/oauth/jwks"))
        .send()
        .await?
        .json()
        .await?;
    let jwk = jwks.find(&kid).ok_or("kid not published in JWKS")?;

    let mut validation = Validation::new(header.alg);
    validation.set_audience(&[client_id]);
    validation.set_issuer(&[issuer]);

    Ok(decode::<AccessTokenClaims>(token, &DecodingKey::from_jwk(jwk)?, &validation)?.claims)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let issuer =
        std::env::var("VOUCH_ISSUER").unwrap_or_else(|_| "https://us.vouch.sh".to_string());
    let client_id =
        std::env::var("VOUCH_CLIENT_ID").expect("VOUCH_CLIENT_ID environment variable is required");

    let client = Client::new();

    // Step 1: Request device code
    let device_response: DeviceResponse = client
        .post(format!("{issuer}/oauth/device"))
        .form(&[
            ("client_id", &client_id),
            ("scope", &"openid email".to_string()),
        ])
        .send()
        .await?
        .json()
        .await?;

    // Step 2: Display instructions to user
    println!("\nTo sign in, visit: {}", device_response.verification_uri);
    println!("Enter code: {}\n", device_response.user_code);

    // Step 3: Poll for token
    let mut interval = Duration::from_secs(device_response.interval.unwrap_or(5));

    loop {
        tokio::time::sleep(interval).await;

        let response = client
            .post(format!("{issuer}/oauth/token"))
            .form(&[
                ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
                ("device_code", &device_response.device_code),
                ("client_id", &client_id),
            ])
            .send()
            .await?;

        if response.status().is_success() {
            let tokens: TokenResponse = response.json().await?;
            println!("Authenticated!");
            println!(
                "Access token: {}...",
                &tokens.access_token[..20.min(tokens.access_token.len())]
            );

            // Fetch user info
            let userinfo_response = client
                .get(format!("{issuer}/oauth/userinfo"))
                .bearer_auth(&tokens.access_token)
                .send()
                .await?;

            if userinfo_response.status().is_success() {
                let userinfo: UserInfoResponse = userinfo_response.json().await?;
                println!("Email: {}", userinfo.email.as_deref().unwrap_or("N/A"));
            } else {
                println!("Email: N/A");
            }

            let at_claims =
                verify_access_token(&client, &issuer, &client_id, &tokens.access_token).await?;
            println!("Hardware verified: {}", at_claims.hardware_verified);
            println!("acr: {}", at_claims.acr.as_deref().unwrap_or("N/A"));
            println!(
                "amr: {}",
                if at_claims.amr.is_empty() {
                    "N/A".to_string()
                } else {
                    at_claims.amr.join(", ")
                }
            );
            return Ok(());
        }

        let error: ErrorResponse = response.json().await?;
        match error.error.as_str() {
            "authorization_pending" => continue,
            "slow_down" => {
                interval += Duration::from_secs(5);
                continue;
            }
            "expired_token" => {
                eprintln!("Device code expired. Please try again.");
                std::process::exit(1);
            }
            "access_denied" => {
                eprintln!("Access denied by user.");
                std::process::exit(1);
            }
            e => {
                eprintln!("Unexpected error: {e}");
                std::process::exit(1);
            }
        }
    }
}
