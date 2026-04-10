import os
import json
import base64

import jwt
from jwt import PyJWKClient
from flask import Flask, request, jsonify

VOUCH_ISSUER = os.environ.get('VOUCH_ISSUER', 'https://us.vouch.sh')
SPIFFE_JWT_AUDIENCE = os.environ.get('SPIFFE_JWT_AUDIENCE', 'spiffe-example')
PORT = int(os.environ.get('PORT', '3000'))

app = Flask(__name__)

# Vouch JWKS client for OIDC JWT verification
vouch_jwks = PyJWKClient(f'{VOUCH_ISSUER}/oauth/jwks')


def decode_token_unverified(token):
    """Decode a JWT without verification to inspect the issuer."""
    return jwt.decode(token, options={
        'verify_signature': False,
        'verify_exp': False,
        'verify_aud': False,
    })


def verify_vouch_token(token):
    """Verify a Vouch OIDC JWT using the Vouch JWKS endpoint."""
    signing_key = vouch_jwks.get_signing_key_from_jwt(token)
    return jwt.decode(
        token,
        signing_key.key,
        algorithms=[signing_key.algorithm_name],
        issuer=VOUCH_ISSUER,
        options={'verify_aud': False},
    )


def verify_spiffe_token(token):
    """Verify a SPIFFE JWT-SVID using the Workload API."""
    from spiffe import WorkloadApiClient

    with WorkloadApiClient() as client:
        svid = client.validate_jwt_svid(token, SPIFFE_JWT_AUDIENCE)
        return {
            'spiffe_id': str(svid.spiffe_id),
            'audience': list(svid.audience),
            'expiry': svid.expiry.isoformat() if svid.expiry else None,
            'claims': svid.claims,
        }


def extract_bearer_token():
    """Extract Bearer token from Authorization header."""
    auth = request.headers.get('Authorization', '')
    if not auth.startswith('Bearer '):
        return None
    return auth[len('Bearer '):]


@app.route('/')
def home():
    return f'''<!DOCTYPE html>
<html><head><title>SPIFFE JWT + Vouch</title></head><body>
<h1>SPIFFE JWT-SVID + Vouch OIDC</h1>
<p>This server accepts Bearer tokens from two identity providers:</p>
<ul>
  <li><strong>Vouch OIDC</strong> &mdash; JWTs issued by <code>{VOUCH_ISSUER}</code></li>
  <li><strong>SPIFFE</strong> &mdash; JWT-SVIDs issued by a SPIRE server</li>
</ul>
<h2>Endpoints</h2>
<ul>
  <li><code>GET /whoami</code> &mdash; Send <code>Authorization: Bearer &lt;token&gt;</code> (auto-detects issuer)</li>
  <li><code>GET /fetch-svid</code> &mdash; Fetches a JWT-SVID from the local Workload API</li>
</ul>
</body></html>'''


@app.route('/whoami')
def whoami():
    token = extract_bearer_token()
    if not token:
        return jsonify({'error': 'Authorization: Bearer <token> header required'}), 401

    try:
        unverified = decode_token_unverified(token)
    except Exception as e:
        return jsonify({'error': f'Invalid token format: {e}'}), 401

    issuer = unverified.get('iss', '')

    # Route to the correct validator based on issuer
    if issuer.startswith('spiffe://'):
        try:
            result = verify_spiffe_token(token)
            return jsonify({
                'identity_type': 'spiffe',
                'spiffe_id': result['spiffe_id'],
                'audience': result['audience'],
                'claims': result.get('claims', {}),
            })
        except Exception as e:
            return jsonify({'error': f'SPIFFE JWT-SVID verification failed: {e}'}), 401
    else:
        try:
            claims = verify_vouch_token(token)
            return jsonify({
                'identity_type': 'vouch',
                'email': claims.get('email', 'unknown'),
                'sub': claims.get('sub', 'unknown'),
                'hardware_verified': claims.get('hardware_verified', False),
                'hardware_aaguid': claims.get('hardware_aaguid'),
                'issuer': claims.get('iss'),
            })
        except Exception as e:
            return jsonify({'error': f'Vouch JWT verification failed: {e}'}), 401


@app.route('/fetch-svid')
def fetch_svid():
    try:
        from spiffe import WorkloadApiClient

        with WorkloadApiClient() as client:
            svid = client.fetch_jwt_svid(audiences={SPIFFE_JWT_AUDIENCE})
            return jsonify({
                'spiffe_id': str(svid.spiffe_id),
                'audience': SPIFFE_JWT_AUDIENCE,
                'token': svid.token,
            })
    except Exception as e:
        return jsonify({'error': f'Failed to fetch JWT-SVID: {e}'}), 500


if __name__ == '__main__':
    print(f'Server running on http://localhost:{PORT}')
    print(f'Vouch issuer: {VOUCH_ISSUER}')
    print(f'SPIFFE JWT audience: {SPIFFE_JWT_AUDIENCE}')
    app.run(host='0.0.0.0', port=PORT)
