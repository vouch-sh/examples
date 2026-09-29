import os
import sys
import time

import jwt
import requests
from jwt import PyJWKClient

VOUCH_ISSUER = os.environ.get("VOUCH_ISSUER", "https://us.vouch.sh")
CLIENT_ID = os.environ.get("VOUCH_CLIENT_ID")
# requests has no default timeout, so an unresponsive issuer would hang the CLI forever.
REQUEST_TIMEOUT = 10

if not CLIENT_ID:
    print("Error: VOUCH_CLIENT_ID environment variable is required")
    sys.exit(1)


jwks_client = PyJWKClient(f"{VOUCH_ISSUER}/oauth/jwks", timeout=REQUEST_TIMEOUT)


def verify_access_token(token):
    """Verify the access token against the issuer's published JWKS.

    hardware_verified is only in the access token, not the id_token. The access token
    is an ES256-signed RFC 9068 JWT, so verify it rather than decoding the payload --
    an agent that acts on an unverified claim is acting on whatever it was handed.
    """
    if jwt.get_unverified_header(token).get("typ", "").lower() != "at+jwt":
        raise ValueError("not an RFC 9068 access token")
    signing_key = jwks_client.get_signing_key_from_jwt(token)
    return jwt.decode(
        token,
        signing_key.key,
        # Vouch signs access tokens with ES256 only. Pin it rather than taking the
        # algorithm from the JWK or the token header.
        algorithms=["ES256"],
        issuer=VOUCH_ISSUER,
        audience=CLIENT_ID,
    )


def fetch_userinfo(access_token):
    resp = requests.get(
        f"{VOUCH_ISSUER}/oauth/userinfo",
        headers={"Authorization": f"Bearer {access_token}"},
        timeout=REQUEST_TIMEOUT,
    )
    resp.raise_for_status()
    return resp.json()


# Step 1: Request device code
response = requests.post(
    f"{VOUCH_ISSUER}/oauth/device",
    data={
        "client_id": CLIENT_ID,
        "scope": "openid email",
    },
    timeout=REQUEST_TIMEOUT,
)
response.raise_for_status()
device_data = response.json()

# Step 2: Display instructions to user
print(f"\nTo sign in, visit: {device_data['verification_uri']}")
print(f"Enter code: {device_data['user_code']}")
# RFC 8628 section 3.3.1: the same page with the code already filled in, for users who
# can open a link (or scan it as a QR code) rather than type the code.
if "verification_uri_complete" in device_data:
    print(f"Or open: {device_data['verification_uri_complete']}")
print()

# Step 3: Poll for token
interval = device_data.get("interval", 5)
while True:
    time.sleep(interval)

    token_response = requests.post(
        f"{VOUCH_ISSUER}/oauth/token",
        data={
            "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
            "device_code": device_data["device_code"],
            "client_id": CLIENT_ID,
        },
        timeout=REQUEST_TIMEOUT,
    )

    if token_response.status_code == 200:
        tokens = token_response.json()
        print("Authenticated!")
        print(f"Access token: {tokens['access_token'][:20]}...")

        # Step 4: Fetch user info and verify the access token's hardware claims
        userinfo = fetch_userinfo(tokens["access_token"])
        at_claims = verify_access_token(tokens["access_token"])
        print(f"Email: {userinfo.get('email', 'N/A')}")
        print(f"Hardware verified: {at_claims.get('hardware_verified', False)}")
        print(f"acr: {at_claims.get('acr', 'N/A')}")
        print(f"amr: {', '.join(at_claims.get('amr', [])) or 'N/A'}")

        # Step 5: Demonstrate post-auth API call with the access token
        print("\n--- Post-auth API call ---")
        userinfo2 = fetch_userinfo(tokens["access_token"])
        print(f"Second userinfo call succeeded: {userinfo2.get('email')}")

        break

    error = token_response.json().get("error")
    if error == "authorization_pending":
        continue
    elif error == "slow_down":
        interval += 5
    elif error == "expired_token":
        print("Device code expired. Please try again.")
        sys.exit(1)
    elif error == "access_denied":
        print("Access denied by user.")
        sys.exit(1)
    else:
        print(f"Error: {token_response.json()}")
        sys.exit(1)
