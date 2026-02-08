<?php

return [
    'vouch' => [
        'base_url' => env('VOUCH_ISSUER', 'https://us.vouch.sh'),
        'client_id' => env('VOUCH_CLIENT_ID'),
        'client_secret' => env('VOUCH_CLIENT_SECRET'),
        'redirect' => env('VOUCH_REDIRECT_URI', 'http://localhost:3000/auth/callback'),
    ],
];
