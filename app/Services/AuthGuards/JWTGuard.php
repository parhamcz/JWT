<?php

namespace App\Services\AuthGuards;

use App\Models\JWT;
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

//    public function __set($key, $value)
//    {
//        $this->data[$key] = $value;
//    }
//
//    public function __get($key)
//    {
//        return $this->data[$key] ?? null;
//    }

    public function __construct(UserProvider $provider, Request $request)
    {
        $this->provider = $provider;
        $this->request = $request;
        $this->encrypter = new Encrypter(config('jwt.private_key'), 'aes-256-cbc');
        $this->access_token = $this->getToken();
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

    protected function getToken()
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

    public function createToken($user, $name = 'default')
    {
        $payload = [
            'sub' => $user->id,
//            'email' => $user->email,
//            'sig' => ,
            'exp' => time() + config('jwt.expiration'),
        ];
        JWT::create([
            'name' => $name,
            'user_id' => $user->id,
            'revoked' => null
        ]);
        $this->access_token = $this->encrypter->encrypt($payload);
        $this->user = $user;
        return $this;
    }

    public function check(): bool
    {
        $data = $this->decrypt($this->getToken());
        if (
            isset($data['sub'])
            && $this->getValidJwt($data['sub'])
            && Carbon::parse($data['exp']) > now()
        ) {
            return true;
        }
        return false;
    }

    protected function getValidJwt($user_id)
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
            && Carbon::parse($data['exp']) > now()
        ) {
            return $valid_token->user;
        }
        return null;
    }

    public function revoke(): bool
    {
        $data = $this->decrypt($this->access_token);
        $token = JWT::where('user_id', $data['sub'])->whereRevoked(null)->first();
        if ($token) {
            $token->revoked = 1;
        }
        $this->forgetUser();
        return $token->save();
    }

    protected function decrypt($token)
    {
        return $this->encrypter->decrypt($token);
    }

    protected function forgetUser()
    {
        $this->user = null;
        $this->access_token = '';
    }
}

