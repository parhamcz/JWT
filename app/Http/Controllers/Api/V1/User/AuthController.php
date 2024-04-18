<?php

namespace App\Http\Controllers\Api\V1\User;

use App\Http\Controllers\Controller;
use App\Http\Requests\LoginRequest;
use App\Http\Requests\RegisterRequest;
use App\Models\JWT;
use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;

class AuthController extends Controller
{
    public function register(RegisterRequest $request)
    {
        try {
            $user = User::create([
                'name' => $request->name,
                'email' => $request->email,
                'password' => $request->password,
            ]);
            $tokens = Auth::guard('api')->createToken($user, 'Access Token')->tokens;
            if (!$tokens) {
                return $this->generateResponse(
                    message: "Token not found.",
                    success: false,
                    status_code: 400
                );
            }
            return $this->generateResponse(
                message: "User Registered successfully.",
                status_code: 201,
                data: ['user' => $user, 'access_token' => $tokens['access_token'], 'refresh_token' => $tokens['refresh_token']]
            );
        } catch (\Exception $e) {
            return $this->generateResponse(
                message: "Error in registering user. Error: " . $e->getMessage(),
                success: false,
                status_code: 500
            );
        }

    }

    public function login(LoginRequest $request)
    {
        try {
            $email = $request->email;
            $password = $request->password;
            $user = User::whereEmail($email)->first();
            if ($user) {
                if ($user->password == $password) { //Hash::check($password, $user->password)
                    $tokens = Auth::guard('api')->createToken($user, 'User Access Token')->tokens;
                    return $this->generateResponse(
                        message: "User logged in successfully.",
                        data: ['user' => $user, 'access_token' => $tokens['access_token'], 'refresh_token' => $tokens['refresh_token']]
                    );
                }
            }
            return $this->generateResponse(
                message: "Invalid Credentials.",
                success: false,
                status_code: 400
            );
        } catch (\Exception $e) {
            return $this->generateResponse(
                message: "Error in logging in the user. Error: " . $e->getMessage(),
                success: false,
                status_code: 500
            );
        }

    }

    public function getUser()
    {
        $user = Auth::guard('api')->user();
        if ($user) {
            return $this->generateResponse(
                message: "User Were Fetched Successfully.",
                data: $user
            );
        }
        return $this->generateResponse(
            message: "User Not found.",
            success: false,
            status_code: 400
        );

    }

    public function logout()
    {
        try {
            $user = Auth::guard('api')->user();
            if ($user) {
                if (Auth::guard('api')->revoke($user)) {
                    return $this->generateResponse(
                        message: "User Logged Out Successfully."
                    );
                }
            }
            return $this->generateResponse(
                message: "User Token Not Found.",
                success: false,
                status_code: 400
            );
        } catch (\Exception $e) {
            return $this->generateResponse(
                message: "Error in logging out the user. Error: " . $e->getMessage(),
                success: false,
                status_code: 500
            );
        }

    }

    public function refreshAccessToken()
    {
        try {
            $tokens = Auth::guard('api')->refreshAccessToken()->tokens;
            if ($tokens) {
                $user = Auth::guard('api')->user();
                return $this->generateResponse(
                    message: "User's Token Renewed successfully.",
                    data: ['user' => $user, 'access_token' => $tokens['access_token'], 'refresh_token' => $tokens['refresh_token']]
                );
            }
            return $this->generateResponse(
                message: "User Refresh Token Not Found.",
                success: false,
                status_code: 400
            );
        } catch (\Exception $e) {
            return $this->generateResponse(
                message: "Error in refreshing access token. Error: " . $e->getMessage(),
                success: false,
                status_code: 500
            );
        }

    }

    public function generateResponse(string $message = null, bool $success = true, int $status_code = 200, $data = null)
    {
        return response()->json([
            'success' => $success,
            'code' => $status_code,
            'message' => $message,
            'data' => $data
        ])->setStatusCode($status_code);
    }
}
