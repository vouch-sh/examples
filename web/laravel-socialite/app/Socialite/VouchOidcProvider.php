<?php

namespace App\Socialite;

use SocialiteProviders\OIDC\Provider;

/**
 * The generic OIDC provider, keeping what RP-initiated logout needs.
 *
 * The parent decodes the ID token for its claims and then discards it, but Vouch only
 * honours post_logout_redirect_uri when the raw ID token comes back as id_token_hint.
 * It also reads end_session_endpoint from discovery without exposing it.
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

    public function endSessionEndpoint(): ?string
    {
        return $this->getOpenIdConfig()['end_session_endpoint'] ?? null;
    }
}
