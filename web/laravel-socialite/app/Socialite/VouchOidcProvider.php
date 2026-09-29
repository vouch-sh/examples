<?php

namespace App\Socialite;

use SocialiteProviders\OIDC\JwtVerificationException;
use SocialiteProviders\OIDC\Provider;

/**
 * The generic OIDC provider, keeping what RP-initiated logout needs.
 *
 * The parent decodes the ID token for its claims and then discards it, but Vouch only
 * honours post_logout_redirect_uri when the raw ID token comes back as id_token_hint.
 * It also reads end_session_endpoint from discovery without exposing it.
 * And its JWT verification never checks the ID token's iss or aud; that is added here.
 */
class VouchOidcProvider extends Provider
{
    public ?string $idToken = null;

    public function getAccessTokenResponse($code)
    {
        $response = parent::getAccessTokenResponse($code);
        $this->idToken = $response['id_token'] ?? null;

        return $response;
    }

    /**
     * The parent checks the signature (and exp, nbf, iat) against the JWKS, but not
     * who issued the ID token or whom it was issued to.
     */
    protected function verifyAndDecodeJWT($jwt)
    {
        $payload = parent::verifyAndDecodeJWT($jwt);

        if (($payload->iss ?? null) !== rtrim($this->getConfig('base_url'), '/')) {
            throw new JwtVerificationException('JWT: issuer mismatch.', 401);
        }
        if (! in_array($this->clientId, (array) ($payload->aud ?? []), true)) {
            throw new JwtVerificationException('JWT: audience mismatch.', 401);
        }

        return $payload;
    }

    public function endSessionEndpoint(): ?string
    {
        return $this->getOpenIdConfig()['end_session_endpoint'] ?? null;
    }
}
