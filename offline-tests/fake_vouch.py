"""A fake Vouch server that checks what the examples send.

Each check mirrors vouch-server's own (paths relative to crates/vouch-server/src):

- ``/oauth/register`` (services/oidc/registration.rs): ``private_key_jwt``,
  ``dpop_bound_access_tokens``, one public P-256 JWK whose ``kid`` is its
  RFC 7638 thumbprint, the expected grant type, ``response_types: []``.
- Client assertions (services/oidc/jwt_bearer/client_auth.rs, FAPI branch):
  ES256, signed by the registered key, ``iss == sub == client_id``, ``aud``
  exactly the issuer string, a ``jti`` never seen before, at most 60 s lived.
- ``/oauth/token`` (handlers/oidc/token.rs, services/oidc/dpop.rs): a DPoP
  proof (``typ: dpop+jwt``, ES256, registered key, ``htm`` POST, ``htu`` the
  token endpoint, fresh, unique ``jti``, no ``ath``). A proof without the
  current nonce gets ``400 use_dpop_nonce`` plus ``DPoP-Nonce``, which the
  real server always does first (``NoncePolicy::Required``).
- ``/v1/*`` (handlers/session.rs): ``Authorization: DPoP``, token ``aud ==
  client_id``, proof ``ath``/``htm``/``htu`` and key matching ``cnf.jkt``.
  The request is captured verbatim so the RFC 9421 signature can be verified
  by vouch-httpsig itself (see httpsig-check/), and each reply carries a
  fresh ``Signature-Nonce`` as the real middleware's does.

Anything unexpected is appended to ``errors`` rather than failing the
request, so a test can report every problem at once.
"""

import base64
import hashlib
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

import jwt
from cryptography.hazmat.primitives.asymmetric import ec

ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
DEVICE_CODE_GRANT = "urn:ietf:params:oauth:grant-type:device_code"
TOKEN_EXCHANGE_GRANT = "urn:ietf:params:oauth:grant-type:token-exchange"
ACCESS_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:access_token"
ROLE_ARN = "arn:aws:iam::111122223333:role/Example"
ORG_ISSUER = "https://acme.us.vouch.sh"
REGISTRATION_ERROR_MARKER = "SECRET-UPSTREAM-DETAIL"
CAPTURED_HEADERS = {
    "authorization",
    "dpop",
    "content-type",
    "content-digest",
    "signature",
    "signature-input",
}

STS_RESPONSE = (
    b'<AssumeRoleWithWebIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">'
    b"<AssumeRoleWithWebIdentityResult><Credentials><AccessKeyId>ASIAEXAMPLE</AccessKeyId>"
    b"<SecretAccessKey>secret</SecretAccessKey><SessionToken>session</SessionToken>"
    b"<Expiration>2026-10-01T00:00:00Z</Expiration></Credentials><AssumedRoleUser>"
    b"<Arn>arn:aws:sts::111122223333:assumed-role/Example/vouch-agent</Arn>"
    b"<AssumedRoleId>AROA:vouch-agent</AssumedRoleId></AssumedRoleUser>"
    b"</AssumeRoleWithWebIdentityResult></AssumeRoleWithWebIdentityResponse>"
)
S3_RESPONSE = (
    b'<ListAllMyBucketsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">'
    b"<Owner><ID>o</ID></Owner><Buckets><Bucket><Name>example-bucket</Name>"
    b"<CreationDate>2026-01-01T00:00:00.000Z</CreationDate></Bucket></Buckets>"
    b"</ListAllMyBucketsResult>"
)


def b64url(data: bytes) -> str:
    """Unpadded base64url."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def thumbprint(jwk: dict) -> str:
    """RFC 7638 thumbprint of an EC JWK."""
    canonical = json.dumps(
        {m: jwk[m] for m in ("crv", "kty", "x", "y")}, separators=(",", ":")
    )
    return b64url(hashlib.sha256(canonical.encode()).digest())


def _form(body: bytes) -> dict:
    return {k: v[0] for k, v in parse_qs(body.decode()).items()}


class FakeVouch:
    """Runs on a background thread until the process exits."""

    def __init__(
        self,
        expected_grant: str,
        bind: str = "127.0.0.1",
        public_host: str = "127.0.0.1",
    ) -> None:
        """Start listening on an ephemeral port."""
        self.expected_grant = expected_grant
        self.issuer_key = ec.generate_private_key(ec.SECP256R1())
        jwk = json.loads(
            jwt.algorithms.ECAlgorithm.to_jwk(self.issuer_key.public_key())
        )
        jwk.update(kid="issuer-1", alg="ES256", use="sig")
        self.issuer_jwk = jwk
        self.clients: dict[str, dict] = {}
        self.registrations = 0
        self.fail_registration = False
        self.errors: list[str] = []
        self.captured: list[dict] = []
        self.nonces: list[str] = []
        self.seen_jtis: set[str] = set()
        self.device_polls = 0
        self.token_nonce = "dpop-nonce-1"
        self.lock = threading.Lock()
        self.server = ThreadingHTTPServer((bind, 0), _handler(self))
        self.issuer = f"http://{public_host}:{self.server.server_port}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def expect(self, condition: bool, what: str) -> None:
        """Record a protocol violation."""
        if not condition:
            self.errors.append(what)

    def access_token(
        self, client_id: str, aud: str, cnf: dict | None = None, **extra: object
    ) -> str:
        """Mint an RFC 9068 access token the way Vouch shapes them."""
        now = int(time.time())
        claims = {
            "iss": self.issuer,
            "sub": "user-1",
            "aud": aud,
            "client_id": client_id,
            "exp": now + 3600,
            "iat": now,
            "scope": "openid email",
            "hardware_verified": True,
            **extra,
        }
        if cnf:
            claims["cnf"] = cnf
        claims = {k: v for k, v in claims.items() if v is not None}
        headers = {"typ": "at+jwt", "kid": "issuer-1"}
        return jwt.encode(claims, self.issuer_key, algorithm="ES256", headers=headers)

    def check_assertion(self, form: dict) -> str | None:
        """Verify a client assertion; returns the client_id or None if unknown."""
        self.expect(
            form.get("client_assertion_type") == ASSERTION_TYPE, "client_assertion_type"
        )
        token = form.get("client_assertion", "")
        try:
            header = jwt.get_unverified_header(token)
            client = self.clients.get(
                jwt.decode(token, options={"verify_signature": False}).get("iss")
            )
            if client is None:
                return None
            self.expect(
                header.get("alg") == "ES256"
                and header.get("kid") == client["jwk"]["kid"],
                "assertion header",
            )
            key = jwt.PyJWK(client["jwk"], algorithm="ES256").key
            claims = jwt.decode(token, key, algorithms=["ES256"], audience=self.issuer)
        except jwt.PyJWTError as exc:
            self.errors.append(f"assertion invalid: {exc}")
            return None
        self.expect(claims["iss"] == claims["sub"], "assertion iss == sub")
        self.expect(claims["aud"] == self.issuer, "assertion aud is the issuer string")
        self.expect(claims["exp"] - claims["iat"] <= 60, "assertion lifetime")
        self.expect(claims["jti"] not in self.seen_jtis, "assertion jti reuse")
        self.seen_jtis.add(claims["jti"])
        if "client_id" in form:
            self.expect(
                form["client_id"] == claims["iss"], "client_id matches assertion"
            )
        return claims["iss"]

    def check_token_dpop(self, proof: str | None, client_id: str) -> dict:
        """Verify a token-endpoint DPoP proof; returns its claims."""
        self.expect(proof is not None, "token request has DPoP")
        header = jwt.get_unverified_header(proof or "")
        self.expect(
            header.get("typ") == "dpop+jwt" and header.get("alg") == "ES256",
            "dpop header",
        )
        self.expect("d" not in header["jwk"], "dpop jwk is public")
        registered = self.clients.get(client_id, {}).get("jwk") or {}
        self.expect(
            thumbprint(header["jwk"]) == registered.get("kid"),
            "dpop key is the registered key",
        )
        key = jwt.PyJWK(header["jwk"], algorithm="ES256").key
        claims = jwt.decode(proof, key, algorithms=["ES256"])
        htu = f"{self.issuer}/oauth/token"
        self.expect(
            claims["htm"] == "POST" and claims["htu"] == htu, f"dpop htm/htu {claims}"
        )
        self.expect(abs(claims["iat"] - time.time()) < 60, "dpop iat")
        self.expect(claims["jti"] not in self.seen_jtis, "dpop jti reuse")
        self.expect("ath" not in claims, "no ath at token endpoint")
        self.seen_jtis.add(claims["jti"])
        return claims

    def register(self, request: dict) -> tuple[int, dict]:
        """Handle RFC 7591 registration."""
        if self.fail_registration:
            return 400, {
                "error": "invalid_client_metadata",
                "error_description": REGISTRATION_ERROR_MARKER,
            }
        self.registrations += 1
        self.expect(
            request.get("token_endpoint_auth_method") == "private_key_jwt",
            "auth method",
        )
        self.expect(request.get("dpop_bound_access_tokens") is True, "dpop bound")
        self.expect(
            request.get("grant_types") == [self.expected_grant],
            f"grant types {request}",
        )
        self.expect(request.get("response_types") == [], "response types")
        keys = request.get("jwks", {}).get("keys", [])
        self.expect(len(keys) == 1, "exactly one key")
        key = keys[0] if keys else {}
        self.expect(key.get("kty") == "EC" and key.get("crv") == "P-256", "P-256 key")
        self.expect(
            bool(key) and key.get("kid") == thumbprint(key),
            "kid is the RFC 7638 thumbprint",
        )
        self.expect("d" not in key, "jwks is public only")
        client_id = f"dcr-{self.registrations}"
        self.clients[client_id] = {"jwk": key}
        return 201, {
            "client_id": client_id,
            "registration_access_token": "rat",
            "registration_client_uri": f"{self.issuer}/oauth/register/{client_id}",
            "token_endpoint_auth_method": "private_key_jwt",
        }

    def device(self, form: dict) -> tuple[int, dict]:
        """Handle RFC 8628 device authorization."""
        if self.check_assertion(form) is None:
            return 401, {
                "error": "invalid_client",
                "error_description": "unknown client",
            }
        return 200, {
            "device_code": "dc-1",
            "user_code": "ABCD-EFGH",
            "verification_uri": f"{self.issuer}/device",
            "verification_uri_complete": f"{self.issuer}/device?user_code=ABCD-EFGH",
            "expires_in": 600,
            "interval": 1,
        }

    def token(self, form: dict, proof: str | None) -> tuple[int, dict, dict]:
        """Handle the device and token-exchange grants."""
        # Like the real server, DPoP (and its nonce) is checked before client
        # authentication, so a nonce retry does not spend the assertion.
        assertion = jwt.decode(
            form.get("client_assertion", ""), options={"verify_signature": False}
        )
        claims = self.check_token_dpop(proof, assertion.get("iss", ""))
        if claims.get("nonce") != self.token_nonce:
            error = {"error": "use_dpop_nonce", "error_description": "nonce required"}
            return 400, error, {"DPoP-Nonce": self.token_nonce}
        client_id = self.check_assertion(form)
        if client_id is None:
            return 401, {"error": "invalid_client"}, {}
        cnf = {"jkt": thumbprint(jwt.get_unverified_header(proof)["jwk"])}
        if form.get("grant_type") == DEVICE_CODE_GRANT:
            self.device_polls += 1
            if self.device_polls == 1:
                return 400, {"error": "authorization_pending"}, {}
            token = self.access_token(client_id, client_id, cnf)
            body = {
                "access_token": token,
                "token_type": "DPoP",
                "expires_in": 3600,
                "email": "user@example.com",
            }
            return 200, body, {}
        self.expect(form.get("grant_type") == TOKEN_EXCHANGE_GRANT, "exchange grant")
        self.expect(
            form.get("subject_token_type") == ACCESS_TOKEN_TYPE, "subject_token_type"
        )
        self.expect(
            form.get("requested_token_type") == ACCESS_TOKEN_TYPE,
            "requested_token_type",
        )
        self.expect(
            "audience" not in form and "resource" not in form, "no audience narrowing"
        )
        subject = jwt.decode(form["subject_token"], options={"verify_signature": False})
        exchanged = self.access_token(
            client_id, client_id, cnf, hardware_verified=subject["hardware_verified"]
        )
        body = {
            "access_token": exchanged,
            "issued_token_type": ACCESS_TOKEN_TYPE,
            "token_type": "DPoP",
            "expires_in": 3600,
        }
        return 200, body, {}

    def credential(
        self, request: BaseHTTPRequestHandler, body: bytes
    ) -> tuple[int, dict, dict]:
        """Check and capture a /v1/credentials call."""
        headers = {
            k: v for k, v in request.headers.items() if k.lower() in CAPTURED_HEADERS
        }
        auth = headers.get("Authorization", "")
        self.expect(auth.startswith("DPoP "), "resource call uses the DPoP scheme")
        token = auth.removeprefix("DPoP ")
        claims = jwt.decode(token, options={"verify_signature": False})
        self.expect(
            claims["aud"] == claims["client_id"], "credential token aud == client_id"
        )
        self.expect(
            claims["client_id"] in self.clients,
            "credential token belongs to a registered client",
        )
        proof = headers.get("DPoP", "")
        proof_jwk = jwt.get_unverified_header(proof)["jwk"]
        proof_claims = jwt.decode(
            proof, jwt.PyJWK(proof_jwk, algorithm="ES256").key, algorithms=["ES256"]
        )
        target = urlsplit(request.path)
        self.expect(
            proof_claims["ath"] == b64url(hashlib.sha256(token.encode()).digest()),
            "ath",
        )
        self.expect(
            proof_claims["htu"] == self.issuer + target.path,
            f"htu {proof_claims['htu']}",
        )
        self.expect(proof_claims["htm"] == request.command, "htm")
        self.expect(
            thumbprint(proof_jwk) == claims["cnf"]["jkt"], "proof key == cnf.jkt"
        )
        if body:
            self.expect(
                headers.get("Content-Type") == "application/json", "content-type"
            )
        self.captured.append(
            {
                "name": f"wire: {request.command} {target.path}",
                "expect": 200,
                "method": request.command,
                "target": request.path,
                "host": request.headers["Host"],
                "headers": headers,
                "body_b64": base64.b64encode(body).decode(),
            }
        )
        nonce = f"sn-{len(self.nonces) + 1}"
        self.nonces.append(nonce)
        if target.path == "/v1/credentials/aws/token":
            self.expect(
                parse_qs(target.query).get("role_arn") == [ROLE_ARN],
                f"role_arn {target.query}",
            )
            id_token = jwt.encode(
                {"iss": ORG_ISSUER, "aud": ORG_ISSUER, "sub": "u@example.com"}, "x" * 32
            )
            out = {"id_token": id_token, "expires_in": 28800}
        elif target.path == "/v1/credentials/github/token":
            out = {
                "token": "ghs_exampletoken0000",
                "expires_at": "2026-10-01T00:00:00Z",
                "expires_in": 3600,
                "permissions": {"contents": "write"},
            }
        else:
            out = {
                "certificate": "ssh-ed25519-cert-v01@openssh.com AAAAexample",
                "valid_for_seconds": 28800,
                "principals": ["user"],
                "serial": 42,
            }
        return 200, out, {"Signature-Nonce": nonce}

    def vectors(self, client_id: str) -> dict:
        """Captured requests in the httpsig-check input format."""
        return {
            "jwk": self.clients[client_id]["jwk"],
            "cases": list(self.captured),
            "nonces": self.nonces,
        }


def _handler(fake: FakeVouch) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args: object) -> None:
            pass

        def _send(
            self, status: int, body: dict | bytes, headers: dict | None = None
        ) -> None:
            data = body if isinstance(body, bytes) else json.dumps(body).encode()
            self.send_response(status)
            self.send_header(
                "Content-Type",
                "text/xml" if isinstance(body, bytes) else "application/json",
            )
            for name, value in (headers or {}).items():
                self.send_header(name, value)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self) -> None:
            with fake.lock:
                if self.path == "/.well-known/openid-configuration":
                    self._send(
                        200,
                        {
                            "issuer": fake.issuer,
                            "jwks_uri": f"{fake.issuer}/oauth/jwks",
                        },
                    )
                elif self.path == "/oauth/jwks":
                    self._send(200, {"keys": [fake.issuer_jwk]})
                elif self.path.startswith("/v1/"):
                    self._send(*fake.credential(self, b""))
                elif urlsplit(self.path).path == "/":
                    # S3 ListBuckets, reached via AWS_ENDPOINT_URL_S3.
                    self._send(200, S3_RESPONSE)
                else:
                    self._send(404, {"error": "not_found"})

        def do_POST(self) -> None:
            with fake.lock:
                length = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(length) if length else b""
                if self.path == "/oauth/register":
                    self._send(*fake.register(json.loads(body)))
                elif self.path == "/oauth/device":
                    self._send(*fake.device(_form(body)))
                elif self.path == "/oauth/token":
                    self._send(*fake.token(_form(body), self.headers.get("DPoP")))
                elif self.path.startswith("/v1/"):
                    self._send(*fake.credential(self, body))
                elif self.path == "/":
                    # STS, reached via AWS_ENDPOINT_URL_STS.
                    action = _form(body).get("Action")
                    fake.expect(action == "AssumeRoleWithWebIdentity", "sts action")
                    self._send(200, STS_RESPONSE)
                else:
                    self._send(404, {"error": "not_found"})

    return Handler
