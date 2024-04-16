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
    private Encrypter $encrypter;
    private string $access_token;
    private string $refresh_token;

//    public function __set($key, $value)
//    {
//        $this->data[$key] = $value;
//    }
//
//    public function __get($key)
//    {
//        return $this->data[$key] ?? null;
//    }
    public array $tokens;

    public function __construct(UserProvider $provider, Request $request)
    {
        $this->provider = $provider;
        $this->request = $request;
        $this->encrypter = new Encrypter(config('jwt.private_key'), 'aes-256-cbc');
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
        $data = $this->encrypter->decrypt($refresh_token);
        if (
            isset($data['sub'])
            && $data
            && $data['type'] === 'refresh_token'
            && Carbon::parse($data['exp']) > now()
        ) {
            $user = User::find($data['sub']);
            if ($user) {
                $this->revokeAccessToken();
                $this->createToken($user,'Renewed Access token');
                return $this;
            }
        }
        return false;
    }

    public function createToken($user, $name = 'default'): static
    {
        $this->revokeAccessToken();
        $payload = [
            'sub' => $user->id,
            'type' => 'access_token',
            'sig' => config('jwt.private_key') . 'JWT' . config('jwt.expiration'),
            'exp' => time() + config('jwt.expiration'),
        ];
        JWT::create([
            'name' => $name,
            'user_id' => $user->id,
            'revoked' => null
        ]);
        $this->access_token = $this->encrypter->encrypt($payload);
        $this->tokens['access_token'] = $this->access_token;
        $this->user = $user;
        $this->firstOrCreateRefreshToken($user);
        return $this;
    }

    protected function firstOrCreateRefreshToken($user): static
    {
        $payload = [
            'sub' => $user->id,
            'type' => 'refresh_token',
            'sig' => config('jwt.refresh_private_key') . 'JWT' . config('jwt.refresh_token_expiration'),
            'exp' => time() + config('jwt.refresh_token_expiration'),
        ];
        RefreshToken::firstOrCreate([
            'user_id' => $user->id,
            'revoked' => null
        ]);
        $this->refresh_token = $this->encrypter->encrypt($payload);
        $this->tokens['refresh_token'] = $this->refresh_token;
        return $this;
    }

    public function check(): bool
    {
        $data = $this->decrypt($this->getToken());
        if (
            isset($data['sub'])
            && $this->getValidJwt($data['sub'])
            && $data['type'] === 'access_token'
            && Carbon::parse($data['exp']) > now()
        ) {
            return true;
        }
        return false;
    }

    protected function getValidJwt($user_id): ?JWT
    {
        return JWT::where('user_id', $user_id)->whereRevoked(null)->first();
    }

    protected function retrieveUserByToken($token)
    {
        $data = $this->decrypt($token);
        $valid_token = $this->getValidJwt($data['sub']);
        if (
            isset($data['sub'])
            && $valid_token
            && $data['type'] === 'access_token'
            && Carbon::parse($data['exp']) > now()
        ) {
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
        $data = $this->decrypt($this->access_token);
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
            $data = $this->decrypt($this->access_token);
            $access_token = JWT::where('user_id', $data['sub'])->whereRevoked(null)->first();
            if ($access_token) {
                $access_token->revoked = 1;
            } else {
                return false;
            }
            return $access_token->save();
        }
        return false;
    }

    protected function decrypt($token)
    {
        return $this->encrypter->decrypt($token);
    }

    protected function forgetUser(): void
    {
        $this->user = null;
        $this->access_token = '';
    }
}

