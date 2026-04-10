import os
import json

import jwt
import requests
from jwt import PyJWKClient
from flask import Flask, request, jsonify

VOUCH_ISSUER = os.environ.get('VOUCH_ISSUER', 'https://us.vouch.sh')
SPIRE_OIDC_ISSUER = os.environ.get('SPIRE_OIDC_ISSUER', '')
SPIFFE_JWT_AUDIENCE = os.environ.get('SPIFFE_JWT_AUDIENCE', 'spiffe-example')
PORT = int(os.environ.get('PORT', '3000'))

app = Flask(__name__)

# Vouch JWKS client
vouch_jwks = PyJWKClient(f'{VOUCH_ISSUER}/oauth/jwks')

# SPIRE OIDC JWKS client (initialized lazily when SPIRE_OIDC_ISSUER is set)
spire_jwks = None
spire_oidc_config = None


def get_spire_jwks():
    """Lazily initialize the SPIRE OIDC JWKS client."""
    global spire_jwks, spire_oidc_config
    if spire_jwks is not None:
        return spire_jwks
    if not SPIRE_OIDC_ISSUER:
        return None

    # Fetch SPIRE OIDC discovery document
    discovery_url = f'{SPIRE_OIDC_ISSUER}/.well-known/openid-configuration'
    resp = requests.get(discovery_url, timeout=10)
    resp.raise_for_status()
    spire_oidc_config = resp.json()

    # Create JWKS client from the discovered JWKS URI
    jwks_uri = spire_oidc_config.get('jwks_uri', f'{SPIRE_OIDC_ISSUER}/keys')
    spire_jwks = PyJWKClient(jwks_uri)
    return spire_jwks


def verify_vouch_token(token):
    """Verify a Vouch OIDC JWT using Vouch's JWKS endpoint."""
    signing_key = vouch_jwks.get_signing_key_from_jwt(token)
    return jwt.decode(
        token,
        signing_key.key,
        algorithms=[signing_key.algorithm_name],
        issuer=VOUCH_ISSUER,
        options={'verify_aud': False},
    )


def verify_spire_token(token):
    """Verify a SPIRE OIDC JWT using SPIRE's JWKS endpoint."""
    jwks = get_spire_jwks()
    if jwks is None:
        raise ValueError('SPIRE_OIDC_ISSUER not configured')

    signing_key = jwks.get_signing_key_from_jwt(token)
    return jwt.decode(
        token,
        signing_key.key,
        algorithms=[signing_key.algorithm_name],
        issuer=SPIRE_OIDC_ISSUER,
        audience=SPIFFE_JWT_AUDIENCE,
    )


def identify_issuer(token):
    """Identify the token issuer without verification."""
    unverified = jwt.decode(token, options={
        'verify_signature': False,
        'verify_exp': False,
        'verify_aud': False,
    })
    return unverified.get('iss', '')


def extract_bearer_token():
    """Extract Bearer token from Authorization header."""
    auth = request.headers.get('Authorization', '')
    if not auth.startswith('Bearer '):
        return None
    return auth[len('Bearer '):]


@app.route('/')
def home():
    spire_status = 'configured' if SPIRE_OIDC_ISSUER else 'not configured'
    return f'''<!DOCTYPE html>
<html><head><title>SPIFFE OIDC Federation + Vouch</title></head><body>
<h1>SPIFFE OIDC Federation + Vouch</h1>
<p>This server trusts two OIDC providers and accepts Bearer tokens from either:</p>
<ul>
  <li><strong>Vouch</strong> &mdash; <code>{VOUCH_ISSUER}</code> (human users)</li>
  <li><strong>SPIRE OIDC</strong> &mdash; <code>{SPIRE_OIDC_ISSUER or "(not set)"}</code> (workloads) [{spire_status}]</li>
</ul>
<h2>Endpoints</h2>
<ul>
  <li><code>GET /resource</code> &mdash; Protected resource (requires Bearer token from either provider)</li>
  <li><code>GET /federation-info</code> &mdash; OIDC discovery metadata from both providers</li>
  <li><code>GET /exchange</code> &mdash; Fetch a SPIFFE JWT-SVID and display it</li>
</ul>
</body></html>'''


@app.route('/resource')
def resource():
    token = extract_bearer_token()
    if not token:
        return jsonify({'error': 'Authorization: Bearer <token> header required'}), 401

    try:
        issuer = identify_issuer(token)
    except Exception as e:
        return jsonify({'error': f'Invalid token format: {e}'}), 401

    # Route to the correct validator based on issuer
    if SPIRE_OIDC_ISSUER and issuer == SPIRE_OIDC_ISSUER:
        try:
            claims = verify_spire_token(token)
            return jsonify({
                'access': 'granted',
                'identity_provider': 'spire',
                'issuer': issuer,
                'subject': claims.get('sub', 'unknown'),
                'claims': {k: v for k, v in claims.items()
                           if k not in ('iss', 'exp', 'iat', 'nbf')},
            })
        except Exception as e:
            return jsonify({'error': f'SPIRE token verification failed: {e}'}), 401
    elif issuer == VOUCH_ISSUER:
        try:
            claims = verify_vouch_token(token)
            return jsonify({
                'access': 'granted',
                'identity_provider': 'vouch',
                'issuer': issuer,
                'email': claims.get('email', 'unknown'),
                'hardware_verified': claims.get('hardware_verified', False),
            })
        except Exception as e:
            return jsonify({'error': f'Vouch token verification failed: {e}'}), 401
    else:
        return jsonify({
            'error': 'Unknown issuer',
            'issuer': issuer,
            'trusted_issuers': [VOUCH_ISSUER, SPIRE_OIDC_ISSUER or '(not configured)'],
        }), 401


@app.route('/federation-info')
def federation_info():
    info = {'vouch': None, 'spire': None}

    # Fetch Vouch OIDC discovery
    try:
        resp = requests.get(
            f'{VOUCH_ISSUER}/.well-known/openid-configuration', timeout=10)
        resp.raise_for_status()
        info['vouch'] = resp.json()
    except Exception as e:
        info['vouch'] = {'error': str(e)}

    # Fetch SPIRE OIDC discovery
    if SPIRE_OIDC_ISSUER:
        try:
            resp = requests.get(
                f'{SPIRE_OIDC_ISSUER}/.well-known/openid-configuration', timeout=10)
            resp.raise_for_status()
            info['spire'] = resp.json()
        except Exception as e:
            info['spire'] = {'error': str(e)}
    else:
        info['spire'] = {'status': 'SPIRE_OIDC_ISSUER not configured'}

    return jsonify(info)


@app.route('/exchange')
def exchange():
    """Fetch a SPIFFE JWT-SVID from the Workload API."""
    try:
        from spiffe import WorkloadApiClient

        with WorkloadApiClient() as client:
            svid = client.fetch_jwt_svid(audiences={SPIFFE_JWT_AUDIENCE})
            return jsonify({
                'spiffe_id': str(svid.spiffe_id),
                'audience': SPIFFE_JWT_AUDIENCE,
                'token': svid.token,
                'hint': 'Use this token as a Bearer token on /resource to access as a SPIFFE workload',
            })
    except Exception as e:
        return jsonify({'error': f'Failed to fetch JWT-SVID: {e}'}), 500


if __name__ == '__main__':
    print(f'OIDC Federation Server running on http://localhost:{PORT}')
    print(f'Trusted Vouch issuer: {VOUCH_ISSUER}')
    print(f'Trusted SPIRE OIDC issuer: {SPIRE_OIDC_ISSUER or "(not configured)"}')
    app.run(host='0.0.0.0', port=PORT)
