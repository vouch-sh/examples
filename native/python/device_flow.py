import os
import sys
import time

import jwt
import requests
from cryptography.hazmat.primitives.asymmetric import ec
from jwt import PyJWKClient

VOUCH_ISSUER = os.environ.get("VOUCH_ISSUER", "https://us.vouch.sh")
CLIENT_ID = os.environ.get("VOUCH_CLIENT_ID")
# requests has no default timeout, so an unresponsive issuer would hang the CLI forever.
REQUEST_TIMEOUT = 10

if not CLIENT_ID:
    print("Error: VOUCH_CLIENT_ID environment variable is required", file=sys.stderr)
    sys.exit(1)


jwks_client = PyJWKClient(f"{VOUCH_ISSUER}/oauth/jwks", timeout=REQUEST_TIMEOUT)


def verify_access_token(token):
    """Verify the access token against the issuer's published JWKS.

    hardware_verified is only in the access token, not the id_token. The access token
    is an ES256-signed RFC 9068 JWT, so verify it rather than decoding the payload --
    an agent that acts on an unverified claim is acting on whatever it was handed.
    """
    header = jwt.get_unverified_header(token)
    if str(header.get("typ")).lower() != "at+jwt":
        raise jwt.InvalidTokenError(f"unexpected token typ: {header.get('typ')}")
    # Vouch signs access tokens with ES256 only. Pin it rather than trusting the header,
    # which is attacker-controlled until the signature has been checked.
    if header.get("alg") != "ES256":
        raise jwt.InvalidAlgorithmError(f"unexpected token alg: {header.get('alg')}")
    signing_key = jwks_client.get_signing_key_from_jwt(token)
    # PyJWT reports a non-EC key under ES256 as a TypeError from deep inside decode.
    # Require a P-256 key here so it is rejected like any other verification failure.
    if not (
        isinstance(signing_key.key, ec.EllipticCurvePublicKey)
        and isinstance(signing_key.key.curve, ec.SECP256R1)
    ):
        raise jwt.InvalidKeyError(f"kid {signing_key.key_id} is not a P-256 key")
    return jwt.decode(
        token,
        signing_key.key,
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
    if resp.status_code != 200:
        raise RuntimeError(f"UserInfo request failed: {resp.status_code}")
    return resp.json()


def oauth_error(response):
    """Return the OAuth ``error`` code from a token endpoint error response, or None.

    A proxy or load balancer in front of the issuer can answer with an HTML or empty
    body, so a failed response is not guaranteed to be JSON.
    """
    try:
        body = response.json()
    except requests.exceptions.JSONDecodeError:
        return None
    return body.get("error") if isinstance(body, dict) else None


def device_flow():
    # Step 1: Request device code
    response = requests.post(
        f"{VOUCH_ISSUER}/oauth/device",
        data={
            "client_id": CLIENT_ID,
            "scope": "openid email",
        },
        timeout=REQUEST_TIMEOUT,
    )
    if response.status_code != 200:
        raise RuntimeError(f"Device request failed: {response.status_code}")
    device_data = response.json()

    # Step 2: Display instructions to user
    print(f"\nTo sign in, visit: {device_data['verification_uri']}")
    print(f"Enter code: {device_data['user_code']}")
    # RFC 8628 section 3.3.1: the same page with the code already filled in, for users
    # who can open a link (or scan it as a QR code) rather than type the code.
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
            hardware_verified = (
                "true" if at_claims.get("hardware_verified") else "false"
            )
            print(f"Email: {userinfo.get('email') or 'N/A'}")
            print(f"Hardware verified: {hardware_verified}")
            print(f"acr: {at_claims.get('acr') or 'N/A'}")
            print(f"amr: {', '.join(at_claims.get('amr') or []) or 'N/A'}")

            # Step 5: Demonstrate post-auth API call with the access token
            print("\n--- Post-auth API call ---")
            userinfo2 = fetch_userinfo(tokens["access_token"])
            print(f"Second userinfo call succeeded: {userinfo2.get('email') or 'N/A'}")

            return

        error = oauth_error(token_response)
        if error is None:
            raise RuntimeError(f"Token request failed: {token_response.status_code}")
        if error == "authorization_pending":
            continue
        if error == "slow_down":
            interval += 5
            continue
        if error == "expired_token":
            raise RuntimeError("Device code expired. Please try again.")
        if error == "access_denied":
            raise RuntimeError("Access denied by user.")
        raise RuntimeError(f"Unexpected error: {error}")


if __name__ == "__main__":
    try:
        device_flow()
    except (RuntimeError, requests.RequestException, jwt.PyJWTError) as err:
        print(f"Error: {err}", file=sys.stderr)
        sys.exit(1)
