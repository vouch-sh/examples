<?php

// The OIDC provider caches Vouch's JWKS here when verifying ID tokens. The framework's
// default store is 'database', which this example has no table for.
return [
    'default' => env('CACHE_STORE', 'file'),
    'stores' => [
        'file' => [
            'driver' => 'file',
            'path' => storage_path('framework/cache/data'),
        ],
    ],
    'prefix' => '',
];
