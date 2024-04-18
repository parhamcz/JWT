<?php

namespace App\Providers;

// use Illuminate\Support\Facades\Gate;
use App\Services\AuthGuards\JWTGuard;
use Illuminate\Encryption\Encrypter;
use Illuminate\Foundation\Support\Providers\AuthServiceProvider as ServiceProvider;
use Illuminate\Support\Facades\Auth;

class AuthServiceProvider extends ServiceProvider
{
    /**
     * The model to policy mappings for the application.
     *
     * @var array<class-string, class-string>
     */
    protected $policies = [
        //
    ];

    /**
     * Register any authentication / authorization services.
     */
    public function boot(): void
    {
        //
        Auth::extend('jwt', function ($app, $name, array $config) {
            $accessTokenEncrypter = new Encrypter(config('jwt.private_key'), 'aes-256-cbc');
            $refreshTokenEncrypter = new Encrypter(config('jwt.refresh_private_key'), 'aes-256-cbc');
            return new JWTGuard(
                Auth::createUserProvider($config['provider']),
                $accessTokenEncrypter,
                $refreshTokenEncrypter,  // Use the same encrypter for refresh tokens (optional)
                $app->make('request')
            );
        });
    }
}
