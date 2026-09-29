import os
from urllib.parse import urlencode, urlsplit

import jwt
from allauth.account.adapter import DefaultAccountAdapter
from allauth.socialaccount.internal import jwtkit
from allauth.socialaccount.providers.openid_connect.views import (
    OpenIDConnectOAuth2Adapter,
)
from jwt import PyJWKClient

VOUCH_ISSUER = os.environ.get('VOUCH_ISSUER', 'https://us.vouch.sh')
VOUCH_CLIENT_ID = os.environ.get('VOUCH_CLIENT_ID', '')
VOUCH_REDIRECT_URI = os.environ.get(
    'VOUCH_REDIRECT_URI', 'http://localhost:3000/accounts/oidc/vouch/login/callback/'
)

jwks_client = PyJWKClient(f'{VOUCH_ISSUER}/oauth/jwks')


def verify_access_token(token):
    """Verify the access token and return its claims.

    hardware_verified is only in the access token, not the id_token. The access token
    is an ES256-signed RFC 9068 JWT, so verify it rather than decoding the payload --
    an unverified decode trusts whatever bytes you were handed.

    The audience is this client's own client_id, which is what Vouch issues when the
    authorization request carries no RFC 8707 `resource` parameter.
    """
    if jwt.get_unverified_header(token).get('typ', '').lower() != 'at+jwt':
        raise ValueError('not an RFC 9068 access token')
    signing_key = jwks_client.get_signing_key_from_jwt(token)
    return jwt.decode(
        token,
        signing_key.key,
        algorithms=[signing_key.algorithm_name],
        issuer=VOUCH_ISSUER,
        audience=VOUCH_CLIENT_ID,
    )


class VouchOIDCAdapter(OpenIDConnectOAuth2Adapter):
    """allauth's OpenID Connect adapter, plus the two things it discards.

    allauth keeps only the decoded ID token claims (in SocialAccount.extra_data) and,
    with SOCIALACCOUNT_STORE_TOKENS, the access token -- never the raw ID token, which
    RP-initiated logout needs as id_token_hint. And it never looks inside the access
    token, which is the only place hardware_verified appears. Both are captured here,
    while the token response is still in hand. It also verifies the ID token signature,
    which allauth skips.
    """

    def _decode_id_token(self, app, id_token):
        """Verify the ID token's signature against the JWKS, as well as iss, aud and exp.

        allauth skips the signature check when it fetched the ID token from the token
        endpoint itself, which OIDC Core 3.1.3.7 permits over TLS. Verify it anyway, as
        the other examples do.
        """
        return jwtkit.verify_and_decode(
            credential=id_token,
            keys_url=self.openid_config['jwks_uri'],
            issuer=self.openid_config['issuer'],
            audience=app.client_id,
            lookup_kid=jwtkit.lookup_kid_jwk,
            verify_signature=True,
        )

    def complete_login(self, request, app, token, **kwargs):
        sociallogin = super().complete_login(request, app, token, **kwargs)
        at_claims = verify_access_token(token.token)
        request.session['vouch_hardware_verified'] = at_claims.get('hardware_verified', False)
        request.session['vouch_id_token'] = kwargs['response'].get('id_token')
        return sociallogin


def post_logout_redirect_uri():
    """The app root on the origin of the registered redirect URI.

    Vouch compares post_logout_redirect_uri as an exact string, so it is derived from
    configuration rather than from the request's Host header.
    """
    redirect = urlsplit(VOUCH_REDIRECT_URI)
    return f'{redirect.scheme}://{redirect.netloc}/'


class VouchAccountAdapter(DefaultAccountAdapter):
    def get_logout_redirect_url(self, request):
        """Send the user to Vouch's end_session endpoint after the local logout.

        Clearing only the Django session leaves the user signed in at Vouch, so the
        next sign-in would complete silently (OIDC RP-Initiated Logout 1.0). allauth
        calls this before it logs the user out, so the ID token is still in the
        session. Vouch shows a confirmation page and redirects back only when
        id_token_hint verifies and post_logout_redirect_uri is registered.
        """
        id_token = request.session.get('vouch_id_token')
        end_session = VouchOIDCAdapter(request, 'vouch').openid_config.get('end_session_endpoint')
        if not id_token or not end_session:
            return super().get_logout_redirect_url(request)
        params = urlencode({
            'id_token_hint': id_token,
            'post_logout_redirect_uri': post_logout_redirect_uri(),
            'client_id': VOUCH_CLIENT_ID,
        })
        return f'{end_session}?{params}'
