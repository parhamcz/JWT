<?php

namespace App\Services\AuthGuards;

use App\Models\JWT;
use App\Models\RefreshToken;
use App\Models\User;
use Carbon\Carbon;
use Illuminate\Auth\GuardHelpers;
use Illuminate\Contracts\Auth\Guard;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Encryption\Encrypter;
use Illuminate\Http\Request;

class JWTGuard implements Guard
{
    use GuardHelpers;

    protected $request;
    private $data;
    private string $access_token;
    private string $refresh_token;
    public array $tokens;
    private Encrypter $accessTokenEncrypter;
    private Encrypter $refreshTokenEncrypter;

    public function __construct(UserProvider $provider, Request $request)
    {
        $this->provider = $provider;
        $this->request = $request;
        $this->accessTokenEncrypter = new Encrypter(config('jwt.private_key'), 'aes-256-cbc');
        $this->refreshTokenEncrypter = new Encrypter(config('jwt.refresh_private_key'), 'aes-256-cbc');
        $this->access_token = $this->getToken() ?? '';
        $this->refresh_token = $this->getToken() ?? '';
        $this->tokens = [
            'access_token' => $this->access_token,
            'refresh_token' => $this->refresh_token,
        ];
    }

    public function user()
    {
        if ($this->user !== null) {
            return $this->user;
        }

        if ($token = $this->getToken()) {
//            $user = $this->provider->retrieveByToken(null, $token); //for custom UserProviders
            $user = $this->retrieveUserByToken($token);
            if ($user) {
                $this->user = $user;
            }
        }

        return $this->user;
    }

    public function validate(array $credentials = [])
    {
        // TODO: Implement validate() method.
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

    public function refreshAccessToken(): bool|static
    {
        $refresh_token = $this->getToken();
        $data = $this->refreshTokenDecrypt($refresh_token);
        if (
            $this->isDataValid($data)
        ) {
            $user = User::find($data['sub']);
            if ($user) {
                $this->revokeAccessToken();
                $this->createToken($user, 'Renewed Access token');
                return $this;
            }
        }
        return false;
    }

    public function createToken($user, $name = 'default'): static
    {
        $this->revokeAccessToken();
        $token = JWT::create([
            'name' => $name,
            'user_id' => $user->id,
            'revoked' => null
        ]);
        $payload = $this->buildPayload(
            sub: $user->id,
            type: 'access_token',
            sig: $token->uuid,
            exp: Carbon::parse(time() + config('jwt.expiration')),
        );
        $this->access_token = $this->accessTokenEncrypter->encrypt($payload);
        $this->tokens['access_token'] = $this->access_token;
        $this->user = $user;
        $this->firstOrCreateRefreshToken($user);
        return $this;
    }

    protected function firstOrCreateRefreshToken($user): static
    {
        $refresh_token = RefreshToken::firstOrCreate([
            'user_id' => $user->id,
            'revoked' => null
        ]);
        $payload = $this->buildPayload(
            sub: $user->id,
            type: 'refresh_token',
            sig: $refresh_token->uuid,
            exp: Carbon::parse(time() + config('jwt.refresh_token_expiration')),
        );
        $this->refresh_token = $this->refreshTokenEncrypter->encrypt($payload);
        $this->tokens['refresh_token'] = $this->refresh_token;
        return $this;
    }

    public function check(): bool
    {
        return $this->isDataValid($this->accessTokenDecrypt($this->getToken()));
    }

    protected function isDataValid(array $data, string $type = 'access_token'): bool
    {
        if (
            isset($data['sub'])
            && $this->getUserValidJwt($data['sub'])
            && $data['type'] === $type
            && JWT::find($data['sig'])->whereRevoked(null)->first()
            && Carbon::parse($data['exp']) > now()
        ) {
            return true;
        }
        return false;
    }

    protected function getUserValidJwt($user_id): ?JWT
    {
        return JWT::where('user_id', $user_id)->whereRevoked(null)->first();
    }

    protected function buildPayload(int $sub, string $type, string $sig, Carbon $exp): array
    {
        return [
            'sub' => $sub,
            'type' => $type,
            'sig' => $sig,
            'exp' => $exp
        ];
    }

    protected function retrieveUserByToken($token)
    {
        $data = $this->accessTokenDecrypt($token);
        $valid_token = $this->getUserValidJwt($data['sub']);
        if ($this->isDataValid($data)) {
            return $valid_token->user ?? null;
        }
        return null;
    }

    public function revoke(): bool
    {
        $access_token_result = $this->revokeAccessToken();
        $refresh_token_result = $this->revokeRefreshToken();
        $this->forgetUser();
        return $refresh_token_result && $access_token_result;
    }

    protected function revokeRefreshToken(): bool
    {
        $data = $this->refreshTokenDecrypt($this->access_token);
        $refresh_token = RefreshToken::where('user_id', $data['sub'])->whereRevoked(null)->first();
        if ($refresh_token) {
            $refresh_token->revoked = 1;
        } else {
            return false;
        }
        return $refresh_token->save();
    }

    protected function revokeAccessToken(): bool
    {
        if ($this->access_token) {
            $data = $this->accessTokenDecrypt($this->access_token);
            $access_token = $this->getUserValidJwt($data['sub']);
            if ($access_token) {
                $access_token->revoked = 1;
            } else {
                return false;
            }
            return $access_token->save();
        }
        return false;
    }

    protected function refreshTokenDecrypt($token)
    {
        return $this->refreshTokenEncrypter->decrypt($token);
    }

    protected function accessTokenDecrypt($token)
    {
        return $this->accessTokenEncrypter->decrypt($token);
    }

    protected function forgetUser(): void
    {
        $this->user = null;
        $this->access_token = '';
    }
}

