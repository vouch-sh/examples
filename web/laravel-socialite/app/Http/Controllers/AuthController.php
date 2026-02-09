<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Laravel\Socialite\Facades\Socialite;
use SocialiteProviders\Manager\Config;

class AuthController extends Controller
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
            ->redirect();
    }

    public function callback(Request $request)
    {
        $vouchUser = Socialite::driver('oidc')->user();

        $request->session()->put('user', [
            'email' => $vouchUser->email,
            'hardware_verified' => $vouchUser->user['hardware_verified'] ?? false,
        ]);

        return redirect('/');
    }

    public function logout(Request $request)
    {
        $request->session()->forget('user');
        return redirect('/');
    }
}
