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
     * @throws JWTException
     */
    public function user(): ?User
    {
        if ($this->user) {
            return $this->user;
        }

        if ($token = $this->getToken()) {
            try {
                $this->user = $this->retrieveUserByToken($token);
            } catch (JWTException $e) {
                throw new JWTException("User could not be found.");
            }
        }

        return $this->user;
    }


    public function refreshAccessToken(): static
    {

        try {
            $this->validateRefreshToken();
            dd('awd');
            $this->revokeAccessToken($this->user);
            $this->createToken($this->user, 'Refreshed Access Token');


        } catch (JWTException $e) {
            // Handle refresh token validation errors
        }

        return $this;
    }


    public function createToken2($user, $name = 'default'): static
    {
        $uuid = Str::uuid();
        $this->revokeAccessToken($user);
        JWT::create([
            'name' => $name,
            'uuid' => $uuid,
            'user_id' => $user->id,
            'revoked' => null
        ]);
        $payload = $this->buildPayload(
            sub: $user->id,
            type: 'access_token',
            sig: $uuid,
            exp: Carbon::parse(time() + config('jwt.expiration')),
        );
        $this->access_token = $this->accessTokenEncrypter->encrypt($payload);
        $this->tokens['access_token'] = $this->access_token;
        $this->user = $user;
        $this->createRefreshToken($user);
        return $this;
    }

    public function createToken(User $user, string $name = 'default'): static
    {
        $this->revokeExistingTokens($user);

        $uuid = Str::uuid();
        $jwt = JWT::create([
            'name' => $name,
            'uuid' => $uuid,
            'user_id' => $user->id,
            'revoked' => null,
        ]);

        $payload = $this->buildPayload($user->id, 'access_token', $uuid, Carbon::parse(time() + config('jwt.expiration')));
        $this->tokens['access_token'] = $this->accessTokenEncrypter->encrypt($payload);
        $this->user = $user;
        $this->createRefreshToken($user);

        return $this;
    }

    protected function createRefreshToken(User $user): void
    {

        $refreshToken = RefreshToken::firstOrCreate([
            'user_id' => $user->id,
            'revoked' => null,
        ], ['uuid' => Str::uuid()]);
        $refreshToken->refresh();

        $payload = $this->buildPayload($user->id, 'refresh_token', $refreshToken->uuid, Carbon::parse(time() + config('jwt.refresh_token_expiration')));

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

    /**
     * @throws JWTException
     */
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
        if(!$this->validateTokenData($data, 'refresh_token')){
            throw new JWTException("Invalid 'refresh_token' token");
        }
    }

    /**
     */
    protected function validateTokenData(array $data, string $type): bool
    {
        if (
            !isset($data['sub'])
            || $data['type'] !== $type
            || !JWT::whereUuid($data['sig'])->whereRevoked(null)->exists()
            || Carbon::parse($data['exp']) <= now()
        ) {
            return false;
        }
        return true;
    }

    protected function revoke(User $user): bool
    {
        return $this->revokeAccessToken($user) && $this->revokeRefreshToken($user);
    }

    protected function revokeAccessToken(User $user): bool
    {
        $accessToken = $user->tokens()->whereRevoked(null)->first();
        if ($accessToken) {
            $accessToken->revoked = 1;
            $accessToken->save();
        }
        return true; // Assuming success even if no token found
    }

    protected function revokeRefreshToken(User $user): bool
    {
        $refreshToken = RefreshToken::where('user_id', $user->id)->whereRevoked(null)->first();
        if ($refreshToken) {
            $refreshToken->revoked = 1;
            $refreshToken->save();
        }
        return true; // Assuming success even if no token found
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

    /**
     * @throws JWTException
     */
    protected function retrieveUserByToken(string $token): User
    {
        $data = $this->accessTokenDecrypt($token);
        $this->validateTokenData($data, 'access_token');

        return User::where('id', $data['sub'])->firstOrFail();
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
        // You can implement logic to handle refresh tokens during login or user retrieval
    }

    /**
     * @throws JWTException
     */
    protected function accessTokenDecrypt(string $token): array
    {
        try {
            return $this->accessTokenEncrypter->decrypt($token);
        } catch (DecryptException $e) {
            throw new JWTException('Invalid access token');
        }
    }

    /**
     * @throws JWTException
     */
    protected function refreshTokenDecrypt(string $token): array
    {
        try {
            return $this->refreshTokenEncrypter->decrypt($token);
        } catch (DecryptException $e) {
            throw new JWTException('Invalid refresh token');
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

