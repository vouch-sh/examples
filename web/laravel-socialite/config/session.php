<?php

return [
    'driver' => env('SESSION_DRIVER', 'file'),
    'lifetime' => 120,
    'expire_on_close' => false,
    // The session holds the ID token; encrypt it at rest in storage/framework/sessions.
    'encrypt' => true,
    'files' => storage_path('framework/sessions'),
    'connection' => null,
    'table' => 'sessions',
    'store' => null,
    'lottery' => [2, 100],
    'cookie' => 'laravel_session',
    'path' => '/',
    'domain' => null,
    // Secure whenever the app is served over HTTPS, judged by the redirect URI Vouch
    // sends the browser back to. Plain-HTTP localhost development keeps working.
    'secure' => parse_url(env('VOUCH_REDIRECT_URI', 'http://localhost:3000/auth/callback'), PHP_URL_SCHEME) === 'https',
    'http_only' => true,
    'same_site' => 'lax',
];
