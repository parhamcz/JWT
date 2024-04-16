<?php

use Illuminate\Support\Facades\Facade;
use Illuminate\Support\ServiceProvider;

return [

    /*
    |--------------------------------------------------------------------------
    | Private Key
    |--------------------------------------------------------------------------
    |
    | This value is the Private key for the custom jwt guard. This key must be 32 chars long due to encryption algorithm.
    |
    */
    'private_key' => 'your-32-chars-private-key-123123',
    /*
    |--------------------------------------------------------------------------
    | Expiration
    |--------------------------------------------------------------------------
    |
    | This value is the expiration duration of the access token in seconds.
    | secs * minutes * days * weeks
    */
    'expiration' => 60 * 60 * 24 * 7,
];
