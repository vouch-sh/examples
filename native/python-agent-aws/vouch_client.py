"""Vouch client for credential-brokering agents.

Vouch only issues credentials from ``/v1/credentials/*`` to a request that
carries an RFC 9421 HTTP Message Signature, and it verifies that signature
against the JWKS registered by the OAuth client the access token was issued
to. A Native application created in the Vouch dashboard has no JWKS, so this
module registers its own client the way the Vouch CLI does:

1. RFC 7591 dynamic registration with an inline P-256 JWKS, ``private_key_jwt``
   client authentication and DPoP-bound access tokens.
2. RFC 8628 device authorization. Every request to ``/oauth/device`` and
   ``/oauth/token`` authenticates with an RFC 7523 client assertion, and the
   token request proves the DPoP key (RFC 9449).
3. Each credential call presents the token with the ``DPoP`` scheme, a DPoP
   proof bound to it, and an RFC 9421 signature made with the same key.

The key and the registration are kept in ``$XDG_STATE_HOME/<client name>/``
(``~/.local/state`` by default) so later runs reuse the registered client.
"""

import base64
import hashlib
import json
import os
import time
import uuid
from pathlib import Path
from urllib.parse import urlencode, urlsplit

import requests
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

TIMEOUT = 10
DEVICE_CODE_GRANT = "urn:ietf:params:oauth:grant-type:device_code"
CLIENT_ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
HTTP_OK = 200
HTTP_CREATED = 201
HTTP_BAD_REQUEST = 400
HTTP_UNAUTHORIZED = 401


class VouchError(Exception):
    """A Vouch request failed. ``code`` is Vouch's machine-readable error code."""

    def __init__(self, message: str, code: str | None = None) -> None:
        """Record the message shown to the user and the server's error code."""
        super().__init__(message)
        self.code = code


def b64url(data: bytes) -> str:
    """Unpadded base64url, as JOSE (RFC 7515) requires."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _json_bytes(value: dict) -> bytes:
    return json.dumps(value, separators=(",", ":")).encode()


def error_code(response: requests.Response) -> str | None:
    """Vouch's error code: ``error`` for OAuth errors, ``code`` for API errors."""
    try:
        body = response.json()
    except ValueError:
        return None
    if not isinstance(body, dict):
        return None
    code = body.get("error") or body.get("code")
    return code if isinstance(code, str) else None


def describe_failure(response: requests.Response) -> str:
    """Summarise a failed response whether or not its body is JSON."""
    try:
        body = response.json()
    except ValueError:
        body = None
    if isinstance(body, dict):
        code = body.get("error") or body.get("code")
        detail = body.get("error_description") or body.get("message")
        if code or detail:
            return (
                f"HTTP {response.status_code} {code or 'error'}: {detail or ''}".rstrip(
                    ": "
                )
            )
    text = response.text.strip()[:200]
    return f"HTTP {response.status_code}: {text or response.reason}"


def _json_response(response: requests.Response, what: str) -> dict:
    try:
        body = response.json()
    except ValueError:
        body = None
    if not isinstance(body, dict):
        msg = f"{what} returned a non-JSON response (HTTP {response.status_code})"
        raise VouchError(msg)
    return body


def _sf_string(value: str) -> str:
    """Serialise an RFC 8941 sf-string."""
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


class ClientKey:
    """The P-256 key used for client assertions, DPoP proofs and request signatures."""

    def __init__(self, private_key: ec.EllipticCurvePrivateKey) -> None:
        """Wrap a P-256 private key and derive its public JWK and key ID."""
        self._private_key = private_key
        numbers = private_key.public_key().public_numbers()
        self.public_jwk = {
            "kty": "EC",
            "crv": "P-256",
            "x": b64url(numbers.x.to_bytes(32, "big")),
            "y": b64url(numbers.y.to_bytes(32, "big")),
        }
        # RFC 7638 thumbprint: the required members in lexicographic order.
        canonical = {name: self.public_jwk[name] for name in ("crv", "kty", "x", "y")}
        self.kid = b64url(hashlib.sha256(_json_bytes(canonical)).digest())

    @classmethod
    def generate(cls) -> "ClientKey":
        """Create a new random P-256 key."""
        return cls(ec.generate_private_key(ec.SECP256R1()))

    @classmethod
    def from_pem(cls, pem: str) -> "ClientKey":
        """Load a key saved by ``to_pem``."""
        key = serialization.load_pem_private_key(pem.encode(), password=None)
        if (
            not isinstance(key, ec.EllipticCurvePrivateKey)
            or key.curve.name != "secp256r1"
        ):
            msg = "saved client key is not a P-256 key"
            raise VouchError(msg)
        return cls(key)

    def to_pem(self) -> str:
        """Serialise the private key as unencrypted PKCS#8 PEM."""
        return self._private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ).decode()

    def jwk(self) -> dict:
        """Public JWK carrying the key ID, as registered with Vouch."""
        return {**self.public_jwk, "kid": self.kid}

    def jws(self, header: dict, claims: dict) -> str:
        """Compact ES256 JWS; JOSE encodes the signature as fixed-size r||s."""
        signing_input = f"{b64url(_json_bytes(header))}.{b64url(_json_bytes(claims))}"
        der = self._private_key.sign(
            signing_input.encode("ascii"), ec.ECDSA(hashes.SHA256())
        )
        r, s = decode_dss_signature(der)
        return (
            f"{signing_input}.{b64url(r.to_bytes(32, 'big') + s.to_bytes(32, 'big'))}"
        )

    def sign_der(self, data: bytes) -> bytes:
        """ECDSA P-256/SHA-256 signature in ASN.1 DER form.

        Vouch verifies ``ecdsa-p256-sha256`` HTTP signatures as DER
        (vouch-httpsig ``EcdsaP256Verifier`` uses ``ECDSA_P256_SHA256_ASN1``),
        not the r||s encoding RFC 9421 section 3.3.4 describes, so a raw r||s
        signature would be rejected.
        """
        return self._private_key.sign(data, ec.ECDSA(hashes.SHA256()))


def client_assertion(key: ClientKey, client_id: str, issuer: str) -> str:
    """RFC 7523 ``private_key_jwt`` assertion; FAPI 2.0 clients must use the issuer as ``aud``."""
    now = int(time.time())
    claims = {
        "iss": client_id,
        "sub": client_id,
        "aud": issuer,
        "jti": str(uuid.uuid4()),
        "iat": now,
        "exp": now + 60,
    }
    return key.jws({"alg": "ES256", "typ": "JWT", "kid": key.kid}, claims)


def dpop_proof(
    key: ClientKey,
    method: str,
    url: str,
    nonce: str | None = None,
    access_token: str | None = None,
) -> str:
    """RFC 9449 DPoP proof. ``htu`` excludes the query and fragment."""
    parts = urlsplit(url)
    claims = {
        "jti": str(uuid.uuid4()),
        "htm": method,
        "htu": f"{parts.scheme}://{parts.netloc}{parts.path}",
        "iat": int(time.time()),
    }
    if nonce:
        claims["nonce"] = nonce
    if access_token:
        claims["ath"] = b64url(hashlib.sha256(access_token.encode("ascii")).digest())
    return key.jws({"typ": "dpop+jwt", "alg": "ES256", "jwk": key.public_jwk}, claims)


def content_digest(body: bytes) -> str:
    """RFC 9530 ``Content-Digest`` field value using SHA-256."""
    return f"sha-256=:{base64.b64encode(hashlib.sha256(body).digest()).decode()}:"


def _authority(url: str) -> str:
    parts = urlsplit(url)
    host = (parts.hostname or "").lower()
    default_port = {"http": 80, "https": 443}.get(parts.scheme)
    if parts.port and parts.port != default_port:
        return f"{host}:{parts.port}"
    return host


def covered_components(method: str, url: str, headers: dict) -> list[tuple[str, str]]:
    """The RFC 9421 components the Vouch CLI signs, with their values.

    ``@method @authority @path @query authorization``, plus ``dpop`` when a
    proof is sent and ``content-type content-digest`` when there is a body.
    Vouch itself requires at least ``@method`` and ``@path``, and
    ``content-digest`` whenever the body is non-empty.
    """
    parts = urlsplit(url)
    components = [
        ('"@method"', method.upper()),
        ('"@authority"', _authority(url)),
        ('"@path"', parts.path or "/"),
        ('"@query"', f"?{parts.query}"),
        ('"authorization"', headers["Authorization"]),
    ]
    if "DPoP" in headers:
        components.append(('"dpop"', headers["DPoP"]))
    if "Content-Digest" in headers:
        components.append(('"content-type"', headers["Content-Type"]))
        components.append(('"content-digest"', headers["Content-Digest"]))
    return components


def signature_headers(
    key: ClientKey, request: tuple[str, str, dict], nonce: str | None = None
) -> dict:
    """``Signature-Input`` and ``Signature`` for a ``(method, url, headers)`` request."""
    components = covered_components(*request)
    # Parameter order matches what vouch-httpsig serialises (alg, created,
    # keyid, nonce); the server rebuilds this string from the parsed header.
    params = (
        f"({' '.join(name for name, _ in components)})"
        f';alg="ecdsa-p256-sha256";created={int(time.time())};keyid={_sf_string(key.kid)}'
    )
    if nonce:
        params += f";nonce={_sf_string(nonce)}"
    lines = [f"{name}: {value}" for name, value in components]
    lines.append(f'"@signature-params": {params}')
    signature = base64.b64encode(
        key.sign_der("\n".join(lines).encode("ascii"))
    ).decode()
    return {"Signature-Input": f"sig1={params}", "Signature": f"sig1=:{signature}:"}


class VouchSession:
    """A registered Vouch client and the DPoP-bound access token it obtained."""

    def __init__(self, issuer: str, client_name: str) -> None:
        """Prepare a session; nothing is sent until ``login``."""
        self.issuer = issuer.rstrip("/")
        self.client_name = client_name
        state_home = Path(
            os.environ.get("XDG_STATE_HOME") or Path.home() / ".local" / "state"
        )
        self.state_file = state_home / client_name / "client.json"
        self._http = requests.Session()
        self._key: ClientKey | None = None
        self._client_id: str | None = None
        self._access_token: str | None = None
        # The token endpoint always demands a DPoP nonce; resource endpoints
        # only issue one when they reject a proof. Signature nonces are
        # single-use and arrive on every signed response.
        self._token_nonce: str | None = None
        self._resource_nonce: str | None = None
        self._signature_nonce: str | None = None

    # -- registration ---------------------------------------------------

    def _load_registration(self) -> bool:
        try:
            state = json.loads(self.state_file.read_text())
            key = ClientKey.from_pem(state["private_key"])
            client_id = state["client_id"]
        except FileNotFoundError:
            return False
        except (OSError, ValueError, KeyError, TypeError) as exc:
            msg = f"cannot read {self.state_file}: {exc}"
            raise VouchError(msg) from exc
        self._key = key
        # A registration belongs to one server and one key; reusing it
        # anywhere else would sign with a key the server does not hold.
        if state.get("issuer") != self.issuer or state.get("kid") != key.kid:
            return False
        self._client_id = client_id
        return True

    def _save_registration(self, registration: dict) -> None:
        state = {
            "issuer": self.issuer,
            "client_id": registration["client_id"],
            "registration_access_token": registration.get("registration_access_token"),
            "registration_client_uri": registration.get("registration_client_uri"),
            "kid": self._key.kid,
            "private_key": self._key.to_pem(),
        }
        self.state_file.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        tmp = self.state_file.with_name(self.state_file.name + ".tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        # O_CREAT leaves an existing file's mode alone.
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w") as f:
            json.dump(state, f, indent=2)
        tmp.replace(self.state_file)

    def _register(self) -> None:
        if self._key is None:
            self._key = ClientKey.generate()
        request = {
            "client_name": self.client_name,
            "token_endpoint_auth_method": "private_key_jwt",
            "grant_types": [DEVICE_CODE_GRANT],
            # No authorization code flow, so no redirect URIs and no "code".
            "response_types": [],
            "dpop_bound_access_tokens": True,
            "jwks": {"keys": [self._key.jwk()]},
        }
        response = self._http.post(
            f"{self.issuer}/oauth/register", json=request, timeout=TIMEOUT
        )
        if response.status_code != HTTP_CREATED:
            msg = f"client registration failed: {describe_failure(response)}"
            raise VouchError(msg, error_code(response))
        registration = _json_response(response, "client registration")
        self._client_id = registration["client_id"]
        self._save_registration(registration)
        print(f"Registered OAuth client {self._client_id} (saved to {self.state_file})")

    # -- device authorization ---------------------------------------------

    def _assertion_fields(self) -> dict:
        return {
            "client_assertion_type": CLIENT_ASSERTION_TYPE,
            "client_assertion": client_assertion(
                self._key, self._client_id, self.issuer
            ),
        }

    def _request_device_code(self) -> requests.Response:
        return self._http.post(
            f"{self.issuer}/oauth/device",
            data={
                "client_id": self._client_id,
                "scope": "openid email",
                **self._assertion_fields(),
            },
            timeout=TIMEOUT,
        )

    def _device_authorization(self) -> dict:
        if not self._load_registration():
            self._register()
            response = self._request_device_code()
        else:
            response = self._request_device_code()
            if (
                response.status_code == HTTP_UNAUTHORIZED
                and error_code(response) == "invalid_client"
            ):
                # The saved client no longer exists on the server (deleted, or
                # the server was reset): register again with the same key.
                self._register()
                response = self._request_device_code()
        if response.status_code != HTTP_OK:
            msg = f"device authorization failed: {describe_failure(response)}"
            raise VouchError(msg, error_code(response))
        return _json_response(response, "device authorization")

    def _token_request(self, form: dict) -> requests.Response:
        url = f"{self.issuer}/oauth/token"
        response = None
        for _ in range(2):
            response = self._http.post(
                url,
                data={**form, **self._assertion_fields()},
                headers={"DPoP": dpop_proof(self._key, "POST", url, self._token_nonce)},
                timeout=TIMEOUT,
            )
            nonce = response.headers.get("DPoP-Nonce")
            if nonce:
                self._token_nonce = nonce
            # RFC 9449 section 8: retry once with the nonce the server supplied.
            is_nonce_challenge = (
                response.status_code == HTTP_BAD_REQUEST
                and error_code(response) == "use_dpop_nonce"
            )
            if not (is_nonce_challenge and nonce):
                break
        return response

    def _poll_for_token(self, device: dict) -> dict:
        interval = int(device.get("interval", 5))
        while True:
            time.sleep(interval)
            response = self._token_request(
                {"grant_type": DEVICE_CODE_GRANT, "device_code": device["device_code"]}
            )
            if response.status_code == HTTP_OK:
                return _json_response(response, "token endpoint")
            code = error_code(response)
            if code == "authorization_pending":
                continue
            if code == "slow_down":
                interval += 5
                continue
            if code == "expired_token":
                msg = "Device code expired. Please try again."
                raise VouchError(msg, code)
            if code == "access_denied":
                msg = "Access denied by user."
                raise VouchError(msg, code)
            msg = f"token request failed: {describe_failure(response)}"
            raise VouchError(msg, code)

    def login(self) -> dict:
        """Register if needed, run the device flow, and keep the access token."""
        device = self._device_authorization()
        print(f"\nTo sign in, visit: {device['verification_uri']}")
        print(f"Enter code: {device['user_code']}\n")
        tokens = self._poll_for_token(device)
        if str(tokens.get("token_type", "")).lower() != "dpop":
            msg = f"expected a DPoP-bound access token, got token_type={tokens.get('token_type')!r}"
            raise VouchError(msg)
        self._access_token = tokens["access_token"]
        print("Authenticated!")
        if tokens.get("email"):
            print(f"Email: {tokens['email']}")
        return tokens

    # -- signed credential calls ------------------------------------------

    def _signed_headers(self, method: str, url: str, body: bytes | None) -> dict:
        headers = {
            "Authorization": f"DPoP {self._access_token}",
            "DPoP": dpop_proof(
                self._key, method, url, self._resource_nonce, self._access_token
            ),
        }
        if body is not None:
            headers["Content-Type"] = "application/json"
            headers["Content-Digest"] = content_digest(body)
        nonce, self._signature_nonce = self._signature_nonce, None
        headers.update(signature_headers(self._key, (method, url, headers), nonce))
        return headers

    def _absorb_nonces(self, response: requests.Response) -> bool:
        """Keep the nonces the server issued; True when a 401 asked for a retry with one."""
        retry = False
        signature_nonce = response.headers.get("Signature-Nonce")
        if signature_nonce:
            self._signature_nonce = signature_nonce
            retry = response.status_code == HTTP_UNAUTHORIZED
        dpop_nonce = response.headers.get("DPoP-Nonce")
        if dpop_nonce:
            self._resource_nonce = dpop_nonce
            retry = retry or response.status_code == HTTP_UNAUTHORIZED
        return retry

    def request(
        self,
        method: str,
        path: str,
        params: dict | None = None,
        body: dict | None = None,
    ) -> dict:
        """Call a signed ``/v1`` endpoint and return its JSON body."""
        if self._access_token is None:
            msg = "not logged in"
            raise VouchError(msg)
        url = f"{self.issuer}{path}"
        if params:
            url += f"?{urlencode(params)}"
        payload = None if body is None else _json_bytes(body)
        for attempt in range(2):
            response = self._http.request(
                method,
                url,
                data=payload,
                headers=self._signed_headers(method, url, payload),
                timeout=TIMEOUT,
            )
            if not (self._absorb_nonces(response) and attempt == 0):
                break
        if not response.ok:
            msg = f"{method} {path} failed: {describe_failure(response)}"
            raise VouchError(msg, error_code(response))
        return _json_response(response, f"{method} {path}")

    def get(self, path: str, params: dict | None = None) -> dict:
        """Signed GET."""
        return self.request("GET", path, params=params)

    def post(self, path: str, body: dict) -> dict:
        """Signed POST with a JSON body."""
        return self.request("POST", path, body=body)
