<?php

namespace App\Http\Controllers\Api\V1\User;

use App\Http\Controllers\Controller;
use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;

class AuthController extends Controller
{
    public function login(Request $request)
    {
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
    }

    public function logout()
    {
        if (Auth::guard('api')->revoke()) {
            return $this->generateResponse(
                message: "User Logged Out Successfully."
            );
        }
        return $this->generateResponse(
            message: "User Token Not Found.",
            success: false,
            status_code: 400
        );
    }

    public function refreshAccessToken()
    {
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
    }

    public function generateResponse(string $message = null, bool $success = true, int $status_code = 200, $data = null)
    {
        return response()->json([
            'success' => $success,
            'code' => $status_code,
            'message' => $message,
            'data' => $data
        ]);
    }
}
