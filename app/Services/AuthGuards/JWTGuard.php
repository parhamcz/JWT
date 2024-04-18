<?php

namespace App\Services\AuthGuards;

use App\Models\JWT;
use App\Models\RefreshToken;
use App\Models\User;
use Carbon\Carbon;
use Illuminate\Auth\GuardHelpers;
use Illuminate\Contracts\Auth\Guard;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Contracts\Encryption\DecryptException;
use Illuminate\Encryption\Encrypter;
use Illuminate\Http\Request;
use Illuminate\Support\Str;

class JWTGuard implements Guard
{
    use GuardHelpers;

    protected $provider;
    protected Encrypter $accessTokenEncrypter;
    protected Encrypter $refreshTokenEncrypter;
    protected Request $request;
    protected $user;
    public array $tokens = [];

    public function __construct(UserProvider $provider, Encrypter $accessTokenEncrypter, Encrypter $refreshTokenEncrypter, Request $request)
    {
        $this->provider = $provider;
        $this->accessTokenEncrypter = $accessTokenEncrypter;
        $this->refreshTokenEncrypter = $refreshTokenEncrypter;
        $this->request = $request;
        $this->initializeAccessToken();
        $this->initializeRefreshToken();
    }

    /**
     */
    public function user(): ?User
    {
        return $this->user;
    }


    /**
     * @throws JWTException
     */
    public function refreshAccessToken(): static
    {
        try {
            $this->validateRefreshToken();
            $this->revokeAccessToken($this->user);
            $this->createToken($this->user, 'Refreshed Access Token');
        } catch (JWTException $e) {
            throw new JWTException($e->getMessage());
        }
        return $this;
    }



    public function createToken(User $user, string $name = 'default'): static
    {
        $this->revokeExistingTokens($user);

        $uuid = Str::uuid();
        JWT::create([
            'name' => $name,
            'uuid' => $uuid,
            'user_id' => $user->id,
            'revoked' => null,
        ]);

        $payload = $this->buildPayload(
            sub: $user->id,
            type: 'access_token',
            sig: $uuid,
            exp: Carbon::parse(time() + config('jwt.expiration'))
        );
        $this->tokens['access_token'] = $this->accessTokenEncrypter->encrypt($payload);
        $this->user = $user;
        $this->createRefreshToken($user);

        return $this;
    }

    protected function createRefreshToken(User $user): void
    {
        $uuid = Str::uuid();
        RefreshToken::create([
            'user_id' => $user->id,
            'revoked' => null,
            'uuid' => $uuid,
        ]);
        $payload = $this->buildPayload(
            sub: $user->id,
            type: 'refresh_token',
            sig: $uuid,
            exp: Carbon::parse(time() + config('jwt.refresh_token_expiration'))
        );

        $this->tokens['refresh_token'] = $this->refreshTokenEncrypter->encrypt($payload);
    }

    public function check(): bool
    {
        try {
            $this->validateAccessToken();
            return true;
        } catch (JWTException $e) {
            return false;
        }
    }

    protected function validateAccessToken(): void
    {
        $data = $this->accessTokenDecrypt($this->getToken());
        $this->validateTokenData($data, 'access_token');
    }

    /**
     * @throws JWTException
     */
    protected function validateRefreshToken(): void
    {

        $data = $this->refreshTokenDecrypt($this->getToken());
        if (!$this->validateTokenData($data, 'refresh_token')) {
            throw new JWTException("Invalid 'refresh_token' token");
        }
    }

    /**
     */
    protected function validateTokenData(array $data, string $type): bool
    {
        $model = $type == 'refresh_token' ? RefreshToken::query() : JWT::query();
        if (
            !isset($data['sub'])
            || $data['type'] !== $type
            || (!$model->whereUuid($data['sig'])->whereRevoked(null)->exists())
            || Carbon::parse($data['exp']) <= now()
        ) {
            return false;
        }
        return true;
    }

    public function revoke(User $user): bool
    {
        return $this->revokeAccessToken($user) && $this->revokeRefreshToken($user);
    }

    protected function revokeAccessToken(User $user): bool
    {
        $accessToken = $user->tokens()->whereRevoked(null)->first();
        if ($accessToken) {
            $accessToken->revoked = 1;
            $accessToken->save();
            return true;
        }
        return false;
    }

    protected function revokeRefreshToken(User $user): bool
    {
        $refreshToken = RefreshToken::where('user_id', $user->id)->whereRevoked(null)->first();
        if ($refreshToken) {
            $refreshToken->revoked = 1;
            $refreshToken->save();
            return true;
        }
        return false;
    }

    protected function revokeExistingTokens(User $user): void
    {
        $this->revokeAccessToken($user);
        $this->revokeRefreshToken($user);
    }

    protected function getToken(): ?string
    {
        $header = $this->request->header('Authorization');

        if (empty($header)) {
            return null;
        }

        if (preg_match('/Bearer\s+(.+)/', $header, $matches)) {
            return $matches[1];
        }

        return null;
    }

    protected function retrieveUserByToken(string $token): ?User
    {
        return $this->retrieveUserByAccessToken($token) ?? $this->retrieveUserByRefreshToken($token);
    }

    protected function retrieveUserByAccessToken(string $token): ?User
    {
        $data = $this->accessTokenDecrypt($token);
        if ($this->validateTokenData($data, 'access_token')) {
            return User::where('id', $data['sub'])->firstOrFail();
        }
        return null;
    }

    protected function retrieveUserByRefreshToken(string $token): ?User
    {
        $data = $this->refreshTokenDecrypt($token);
        if ($this->validateTokenData($data, 'refresh_token')) {
            return User::where('id', $data['sub'])->firstOrFail();
        }
        return null;
    }

    protected function buildPayload(int $sub, string $type, string $sig, Carbon $exp): array
    {
        return [
            'sub' => $sub,
            'type' => $type,
            'sig' => $sig,
            'exp' => $exp,
        ];
    }

    protected function initializeAccessToken(): void
    {
        $token = $this->getToken();
        if ($token) {
            try {
                $this->user = $this->retrieveUserByToken($token);
                $this->tokens['access_token'] = $token;
            } catch (JWTException $e) {
                $this->forgetUser();
            }
        }
    }

    protected function initializeRefreshToken(): void
    {
        $token = $this->getToken();
        if ($token) {
            try {
                $this->user = $this->retrieveUserByToken($token);
                $this->tokens['refresh_token'] = $token;
            } catch (JWTException $e) {
                $this->forgetUser();
            }
        }
    }
    protected function accessTokenDecrypt(string $token): ?array
    {
        try {
            return $this->accessTokenEncrypter->decrypt($token);
        } catch (DecryptException $e) {
            return [];
//            throw new JWTException('Invalid access token');
        }
    }

    protected function refreshTokenDecrypt(string $token): ?array
    {
        try {
            return $this->refreshTokenEncrypter->decrypt($token);
        } catch (DecryptException $e) {
            return [];
//            throw new JWTException('Invalid refresh token');
        }
    }

    protected function forgetUser(): void
    {
        $this->user = null;
        $this->tokens = [];
    }

    public function validate(array $credentials = [])
    {
        // TODO: Implement validate() method.
    }
}

