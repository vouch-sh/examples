<?php

namespace App\Http\Controllers;

use Firebase\JWT\JWK;
use Firebase\JWT\JWT;
use Illuminate\Http\Request;
use Laravel\Socialite\Facades\Socialite;
use SocialiteProviders\Manager\Config;

class AuthController extends \Illuminate\Routing\Controller
{
    public function home(Request $request)
    {
        $user = $request->session()->get('user');

        if ($user) {
            return response()->make(
                '<html><head><title>Vouch + Laravel</title></head><body>' .
                '<h1>Vouch OIDC + Laravel + Socialite</h1>' .
                '<p>Signed in as ' . htmlspecialchars($user['email']) . '</p>' .
                ($user['hardware_verified'] ? '<p><strong>Hardware Verified</strong></p>' : '') .
                '<ul>' .
                '<li>email: ' . htmlspecialchars($user['email']) . '</li>' .
                '<li>email_verified: ' . var_export($user['email_verified'], true) . '</li>' .
                '<li>sub: ' . htmlspecialchars($user['sub']) . '</li>' .
                '<li>amr: ' . htmlspecialchars(implode(', ', $user['amr']) ?: 'N/A') . '</li>' .
                '<li>acr: ' . htmlspecialchars($user['acr'] ?? 'N/A') . '</li>' .
                '<li>hardware_verified: ' . var_export($user['hardware_verified'], true) . '</li>' .
                '</ul>' .
                '<form method="POST" action="/logout"><input type="hidden" name="_token" value="' . csrf_token() . '">' .
                '<button type="submit">Sign out</button></form>' .
                '</body></html>'
            );
        }

        return response()->make(
            '<html><head><title>Vouch + Laravel</title></head><body>' .
            '<h1>Vouch OIDC + Laravel + Socialite</h1>' .
            '<a href="/auth/redirect">Sign in with Vouch</a>' .
            '</body></html>'
        );
    }

    /**
     * @return \App\Socialite\VouchOidcProvider
     */
    private function vouch()
    {
        $config = new Config(
            config('services.oidc.client_id'),
            config('services.oidc.client_secret'),
            config('services.oidc.redirect'),
            [
                'base_url' => config('services.oidc.base_url'),
                // Off by default in the provider, which would otherwise trust the ID
                // token's payload unverified. The JWKS is cached in the file cache.
                'verify_jwt' => true,
            ]
        );

        return Socialite::driver('oidc')->setConfig($config);
    }

    public function redirect()
    {
        return $this->vouch()
            ->scopes(['openid', 'email'])
            ->enablePKCE()
            ->redirect();
    }

    public function callback(Request $request)
    {
        $provider = $this->vouch()->enablePKCE();
        $vouchUser = $provider->user();

        $claims = $this->verifyAccessToken($vouchUser->token, $provider->jwks());
        // The raw user is the ID token payload.
        $idClaims = $vouchUser->getRaw();

        $request->session()->put('user', [
            'email' => $vouchUser->email,
            'email_verified' => $idClaims['email_verified'] ?? false,
            'sub' => $idClaims['sub'],
            'acr' => $idClaims['acr'] ?? null,
            'amr' => $idClaims['amr'] ?? [],
            'hardware_verified' => $claims['hardware_verified'] ?? false,
        ]);
        // Kept for RP-initiated logout: Vouch only honours post_logout_redirect_uri
        // when a verified id_token_hint identifies the client.
        $request->session()->put('id_token', $provider->idToken);

        return redirect('/');
    }

    /**
     * Verify a Vouch access token against the issuer's published JWKS.
     *
     * hardware_verified is only in the access token, not the id_token. The access token
     * is an ES256-signed RFC 9068 JWT, so verify it rather than decoding the payload --
     * an unverified decode trusts whatever bytes you were handed.
     *
     * The audience is this client's own client_id, which is what Vouch issues when the
     * authorization request carries no RFC 8707 resource parameter.
     */
    private function verifyAccessToken(string $token, array $jwks): array
    {
        $issuer = rtrim(config('services.oidc.base_url'), '/');

        // RFC 9068 access tokens carry typ: at+jwt. Requiring it rejects id_tokens,
        // which are not bearer credentials.
        $header = json_decode(base64_decode(strtr(explode('.', $token)[0], '-_', '+/')), true);
        if (strtolower($header['typ'] ?? '') !== 'at+jwt') {
            abort(500, 'Not an RFC 9068 access token');
        }

        $claims = (array) JWT::decode($token, JWK::parseKeySet($jwks));

        if (($claims['iss'] ?? null) !== $issuer) {
            abort(500, 'Access token issuer mismatch');
        }
        $audience = (array) ($claims['aud'] ?? []);
        if (! in_array(config('services.oidc.client_id'), $audience, true)) {
            abort(500, 'Access token audience mismatch');
        }

        return $claims;
    }

    /**
     * Sign out locally, then at Vouch (OIDC RP-Initiated Logout 1.0).
     *
     * Clearing only the local session leaves the user signed in at Vouch, so the next
     * sign-in would complete silently. Vouch shows a confirmation page and redirects
     * back only when id_token_hint verifies and post_logout_redirect_uri is registered.
     */
    /**
     * The app root on the origin of the registered redirect URI. Vouch compares
     * post_logout_redirect_uri as an exact string, so it is derived from configuration
     * rather than from the request's Host header.
     */
    private function postLogoutRedirectUri(): string
    {
        $redirect = parse_url(config('services.oidc.redirect'));
        $port = isset($redirect['port']) ? ':' . $redirect['port'] : '';

        return $redirect['scheme'] . '://' . $redirect['host'] . $port . '/';
    }

    public function logout(Request $request)
    {
        $idToken = $request->session()->pull('id_token');
        $request->session()->forget('user');

        $endSession = $this->vouch()->endSessionEndpoint();
        if (! $endSession || ! $idToken) {
            return redirect('/');
        }

        return redirect()->away($endSession . '?' . http_build_query([
            'id_token_hint' => $idToken,
            'post_logout_redirect_uri' => $this->postLogoutRedirectUri(),
            'client_id' => config('services.oidc.client_id'),
        ]));
    }
}
