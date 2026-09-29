<?php

namespace App\Socialite;

use SocialiteProviders\Manager\SocialiteWasCalled;

/**
 * Registers VouchOidcProvider as the 'oidc' driver, in place of the package's own
 * OIDCExtendSocialite listener.
 */
class VouchExtendSocialite
{
    public function handle(SocialiteWasCalled $socialiteWasCalled): void
    {
        $socialiteWasCalled->extendSocialite('oidc', VouchOidcProvider::class);
    }
}
