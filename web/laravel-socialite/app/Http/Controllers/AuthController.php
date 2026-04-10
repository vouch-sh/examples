<?php

namespace App\Http\Controllers;

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

        // Hardware claims are in the access token JWT (RFC 9068), not the id_token.
        $hardwareVerified = false;
        $parts = explode('.', $vouchUser->token);
        if (count($parts) === 3) {
            $payload = json_decode(base64_decode(strtr($parts[1], '-_', '+/')), true);
            $hardwareVerified = $payload['hardware_verified'] ?? false;
        }

        $request->session()->put('user', [
            'email' => $vouchUser->email,
            'hardware_verified' => $hardwareVerified,
        ]);

        return redirect('/');
    }

    public function logout(Request $request)
    {
        $request->session()->forget('user');
        return redirect('/');
    }
}
