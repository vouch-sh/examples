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
                '<p>Welcome, ' . htmlspecialchars($user['name']) . '</p>' .
                '<p>Email: ' . htmlspecialchars($user['email']) . '</p>' .
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
            config('services.vouch.client_id'),
            config('services.vouch.client_secret'),
            config('services.vouch.redirect'),
            ['base_url' => config('services.vouch.base_url')]
        );

        return Socialite::driver('openid-connect')
            ->setConfig($config)
            ->scopes(['openid', 'email', 'profile'])
            ->redirect();
    }

    public function callback(Request $request)
    {
        $vouchUser = Socialite::driver('openid-connect')->user();

        $request->session()->put('user', [
            'name' => $vouchUser->name,
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
