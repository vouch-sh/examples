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
struct UserInfo {
    name: Option<String>,
    email: Option<String>,
    hardware_verified: Option<bool>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let issuer = std::env::var("VOUCH_ISSUER")
        .expect("VOUCH_ISSUER environment variable is required");
    let client_id = std::env::var("VOUCH_CLIENT_ID")
        .expect("VOUCH_CLIENT_ID environment variable is required");

    let client = Client::new();

    // Step 1: Request device code
    let device_response: DeviceResponse = client
        .post(format!("{issuer}/oauth/device"))
        .form(&[("client_id", &client_id), ("scope", &"openid email profile".to_string())])
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
            println!("Access token: {}...", &tokens.access_token[..20.min(tokens.access_token.len())]);

            // Fetch user info
            let userinfo: UserInfo = client
                .get(format!("{issuer}/oauth/userinfo"))
                .bearer_auth(&tokens.access_token)
                .send()
                .await?
                .json()
                .await?;

            println!("Name: {}", userinfo.name.as_deref().unwrap_or("N/A"));
            println!("Email: {}", userinfo.email.as_deref().unwrap_or("N/A"));
            println!("Hardware verified: {}", userinfo.hardware_verified.unwrap_or(false));
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
