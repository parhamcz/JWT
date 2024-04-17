<?php

use Illuminate\Support\Facades\Facade;
use Illuminate\Support\ServiceProvider;

return [

    /*
    |--------------------------------------------------------------------------
    | Private Key
    |--------------------------------------------------------------------------
    |
    | This value is the Private key for the custom jwt guard.
    | This key must be 32 chars long due to encryption algorithm.
    |
    */
    'private_key' => 'your-32-chars-private-key-123123',
    /*
    |--------------------------------------------------------------------------
    | Refresh Private Key
    |--------------------------------------------------------------------------
    |
    | This value is the Private key for the custom jwt guards refresh token.
    | This key must be 32 chars long due to encryption algorithm.
    |
    */
    'refresh_private_key' => 'your-32-chars-private-key-234234',
    /*
    |--------------------------------------------------------------------------
    | Token Expiration
    |--------------------------------------------------------------------------
    |
    | This value is the expiration duration of the access token in seconds.
    | secs * minutes * days * weeks
    */
    'expiration' => 60 * 60 * 24 * 7,
    /*
    |--------------------------------------------------------------------------
    | Refresh Token Expiration
    |--------------------------------------------------------------------------
    |
    | This value is the expiration duration of the refresh token in seconds.
    | secs * minutes * days * months
    */
    'refresh_token_expiration' => 60 * 60 * 24 * 30,
];
