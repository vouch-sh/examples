<?php

namespace App\Http\Controllers;

use Firebase\JWT\JWK;
use Firebase\JWT\JWT;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Http;
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
                ($user['acr'] ? '<p>acr: ' . htmlspecialchars($user['acr']) . '</p>' : '') .
                ($user['amr'] ? '<p>amr: ' . htmlspecialchars(implode(', ', $user['amr'])) . '</p>' : '') .
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

    public function redirect()
    {
        $config = new Config(
            config('services.oidc.client_id'),
            config('services.oidc.client_secret'),
            config('services.oidc.redirect'),
            ['base_url' => config('services.oidc.base_url')]
        );

        return Socialite::driver('oidc')
            ->setConfig($config)
            ->scopes(['openid', 'email'])
            ->enablePKCE()
            ->redirect();
    }

    public function callback(Request $request)
    {
        $config = new Config(
            config('services.oidc.client_id'),
            config('services.oidc.client_secret'),
            config('services.oidc.redirect'),
            ['base_url' => config('services.oidc.base_url')]
        );

        $vouchUser = Socialite::driver('oidc')
            ->setConfig($config)
            ->enablePKCE()
            ->user();

        $claims = $this->verifyAccessToken($vouchUser->token);

        $request->session()->put('user', [
            'email' => $vouchUser->email,
            'hardware_verified' => $claims['hardware_verified'] ?? false,
            'acr' => $claims['acr'] ?? null,
            'amr' => $claims['amr'] ?? [],
        ]);

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
    private function verifyAccessToken(string $token): array
    {
        $issuer = rtrim(config('services.oidc.base_url'), '/');

        // RFC 9068 access tokens carry typ: at+jwt. Requiring it rejects id_tokens,
        // which are not bearer credentials.
        $header = json_decode(base64_decode(strtr(explode('.', $token)[0], '-_', '+/')), true);
        if (strtolower($header['typ'] ?? '') !== 'at+jwt') {
            abort(500, 'Not an RFC 9068 access token');
        }

        // Refetched per login to keep the example short. A real app should cache this
        // and only refetch when it encounters an unknown `kid`.
        $jwks = Http::get($issuer . '/oauth/jwks')->throw()->json();
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

    public function logout(Request $request)
    {
        $request->session()->forget('user');
        return redirect('/');
    }
}
