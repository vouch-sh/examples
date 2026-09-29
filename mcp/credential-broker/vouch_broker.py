"""The broker's own Vouch client: token exchange and signed credential calls.

Vouch's ``/v1/credentials/*`` endpoints need an access token that is audienced
to Vouch (``aud`` equal to the token's own ``client_id``), hardware-verified,
and presented with an RFC 9421 signature made with a key from the JWKS of the
client the token was issued to. A token an MCP client obtained for this broker
satisfies none of the first and last: its ``aud`` is the broker, and it
belongs to the MCP client.

So the broker registers itself (RFC 7591) with a P-256 JWKS, ``private_key_jwt``
authentication, DPoP-bound tokens and the RFC 8693 token-exchange grant, and
for each credential call exchanges the caller's token for one issued to the
broker. Vouch copies ``hardware_verified`` from the subject token, binds the
new token to the broker's DPoP key, and sets its ``aud`` to the broker's
client_id, so the broker can sign the credential request with its own key.

The key and registration are kept in ``$XDG_STATE_HOME/<client name>/``.
"""

import asyncio
import base64
import hashlib
import json
import logging
import os
import time
import uuid
from pathlib import Path
from urllib.parse import urlencode, urlsplit

import httpx
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

logger = logging.getLogger("vouch_broker")

TIMEOUT = 10
TOKEN_EXCHANGE_GRANT = "urn:ietf:params:oauth:grant-type:token-exchange"
ACCESS_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:access_token"
CLIENT_ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
HTTP_OK = 200
HTTP_CREATED = 201
HTTP_BAD_REQUEST = 400
HTTP_UNAUTHORIZED = 401


class BrokerError(Exception):
    """A Vouch call failed.

    The message is fixed text safe to return to an MCP client; the upstream
    response is only logged, never passed through.
    """

    def __init__(self, message: str, status: int | None = None) -> None:
        """Record the client-facing message and the upstream HTTP status."""
        super().__init__(message)
        self.status = status


def b64url(data: bytes) -> str:
    """Unpadded base64url, as JOSE (RFC 7515) requires."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _json_bytes(value: dict) -> bytes:
    return json.dumps(value, separators=(",", ":")).encode()


def _error_code(response: httpx.Response) -> str | None:
    try:
        body = response.json()
    except ValueError:
        return None
    if not isinstance(body, dict):
        return None
    code = body.get("error") or body.get("code")
    return code if isinstance(code, str) else None


def _log_failure(what: str, response: httpx.Response) -> None:
    logger.warning("%s: HTTP %s %s", what, response.status_code, response.text[:500])


def _json_response(response: httpx.Response, what: str) -> dict:
    try:
        body = response.json()
    except ValueError:
        body = None
    if not isinstance(body, dict):
        _log_failure(f"{what} returned non-JSON", response)
        raise BrokerError(f"{what} returned an invalid response", response.status_code)
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
            raise ValueError(msg)
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


class Broker:
    """The broker's registered Vouch client."""

    def __init__(self, issuer: str, client_name: str) -> None:
        """Prepare the client; registration happens on the first credential call."""
        self.issuer = issuer.rstrip("/")
        self.client_name = client_name
        state_home = Path(
            os.environ.get("XDG_STATE_HOME") or Path.home() / ".local" / "state"
        )
        self.state_file = state_home / client_name / "client.json"
        self._lock = asyncio.Lock()
        self._key: ClientKey | None = None
        self._client_id: str | None = None
        self._registered_this_run = False
        # The token endpoint always demands a DPoP nonce; resource endpoints
        # only issue one when they reject a proof. Signature nonces are
        # single-use and arrive on every signed response.
        self._token_nonce: str | None = None
        self._resource_nonce: str | None = None
        self._signature_nonce: str | None = None

    # -- registration ---------------------------------------------------

    def _load_registration(self) -> None:
        try:
            state = json.loads(self.state_file.read_text())
            key = ClientKey.from_pem(state["private_key"])
            client_id = state["client_id"]
        except FileNotFoundError:
            return
        except (OSError, ValueError, KeyError, TypeError):
            logger.exception("cannot read %s", self.state_file)
            msg = "broker client state is unreadable"
            raise BrokerError(msg) from None
        self._key = key
        # A registration belongs to one server and one key; reusing it
        # anywhere else would sign with a key the server does not hold.
        if state.get("issuer") == self.issuer and state.get("kid") == key.kid:
            self._client_id = client_id

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

    async def _register(self, http: httpx.AsyncClient) -> None:
        if self._key is None:
            self._key = ClientKey.generate()
        request = {
            "client_name": self.client_name,
            "token_endpoint_auth_method": "private_key_jwt",
            "grant_types": [TOKEN_EXCHANGE_GRANT],
            # No authorization code flow, so no redirect URIs and no "code".
            "response_types": [],
            "dpop_bound_access_tokens": True,
            "jwks": {"keys": [self._key.jwk()]},
        }
        response = await http.post(f"{self.issuer}/oauth/register", json=request)
        if response.status_code != HTTP_CREATED:
            _log_failure("client registration failed", response)
            msg = "broker client registration failed"
            raise BrokerError(msg, response.status_code)
        registration = _json_response(response, "client registration")
        self._client_id = registration["client_id"]
        self._registered_this_run = True
        self._save_registration(registration)
        logger.info(
            "registered OAuth client %s (saved to %s)", self._client_id, self.state_file
        )

    async def _ensure_registered(self, http: httpx.AsyncClient) -> None:
        async with self._lock:
            if self._client_id is None:
                self._load_registration()
            if self._client_id is None:
                await self._register(http)

    # -- token exchange ---------------------------------------------------

    async def _token_request(
        self, http: httpx.AsyncClient, form: dict
    ) -> httpx.Response:
        url = f"{self.issuer}/oauth/token"
        response = None
        for _ in range(2):
            assertion = client_assertion(self._key, self._client_id, self.issuer)
            response = await http.post(
                url,
                data={
                    **form,
                    "client_assertion_type": CLIENT_ASSERTION_TYPE,
                    "client_assertion": assertion,
                },
                headers={"DPoP": dpop_proof(self._key, "POST", url, self._token_nonce)},
            )
            nonce = response.headers.get("DPoP-Nonce")
            if nonce:
                self._token_nonce = nonce
            # RFC 9449 section 8: retry once with the nonce the server supplied.
            is_nonce_challenge = (
                response.status_code == HTTP_BAD_REQUEST
                and _error_code(response) == "use_dpop_nonce"
            )
            if not (is_nonce_challenge and nonce):
                break
        return response

    async def _exchange(self, http: httpx.AsyncClient, subject_token: str) -> str:
        form = {
            "grant_type": TOKEN_EXCHANGE_GRANT,
            "subject_token": subject_token,
            "subject_token_type": ACCESS_TOKEN_TYPE,
            "requested_token_type": ACCESS_TOKEN_TYPE,
        }
        response = await self._token_request(http, form)
        if (
            response.status_code == HTTP_UNAUTHORIZED
            and _error_code(response) == "invalid_client"
            and not self._registered_this_run
        ):
            # The saved client no longer exists on the server (deleted, or the
            # server was reset): register again with the same key.
            async with self._lock:
                await self._register(http)
            response = await self._token_request(http, form)
        if response.status_code != HTTP_OK:
            _log_failure("token exchange failed", response)
            msg = "Vouch token exchange failed"
            raise BrokerError(msg, response.status_code)
        tokens = _json_response(response, "token exchange")
        if str(tokens.get("token_type", "")).lower() != "dpop":
            logger.warning(
                "token exchange returned token_type=%r", tokens.get("token_type")
            )
            msg = "Vouch token exchange returned an unexpected token type"
            raise BrokerError(msg)
        return tokens["access_token"]

    # -- signed credential calls ------------------------------------------

    def _signed_headers(
        self, method: str, url: str, token: str, body: bytes | None
    ) -> dict:
        headers = {
            "Authorization": f"DPoP {token}",
            "DPoP": dpop_proof(self._key, method, url, self._resource_nonce, token),
        }
        if body is not None:
            headers["Content-Type"] = "application/json"
            headers["Content-Digest"] = content_digest(body)
        nonce, self._signature_nonce = self._signature_nonce, None
        headers.update(signature_headers(self._key, (method, url, headers), nonce))
        return headers

    def _absorb_nonces(self, response: httpx.Response) -> bool:
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

    async def credential(
        self,
        subject_token: str,
        request: tuple[str, str],
        params: dict | None = None,
        body: dict | None = None,
    ) -> dict:
        """Exchange ``subject_token`` and call the signed ``(method, path)`` endpoint."""
        method, path = request
        url = f"{self.issuer}{path}"
        if params:
            url += f"?{urlencode(params)}"
        payload = None if body is None else _json_bytes(body)
        async with httpx.AsyncClient(timeout=TIMEOUT) as http:
            await self._ensure_registered(http)
            token = await self._exchange(http, subject_token)
            for attempt in range(2):
                response = await http.request(
                    method,
                    url,
                    content=payload,
                    headers=self._signed_headers(method, url, token, payload),
                )
                if not (self._absorb_nonces(response) and attempt == 0):
                    break
        if not response.is_success:
            _log_failure(f"{method} {path} failed", response)
            msg = f"Vouch rejected the {path} request"
            raise BrokerError(msg, response.status_code)
        return _json_response(response, f"{method} {path}")
