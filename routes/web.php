<?php

use Illuminate\Encryption\Encrypter;
use Illuminate\Support\Facades\Route;

/*
|--------------------------------------------------------------------------
| Web Routes
|--------------------------------------------------------------------------
|
| Here is where you can register web routes for your application. These
| routes are loaded by the RouteServiceProvider and all of them will
| be assigned to the "web" middleware group. Make something great!
|
*/

Route::get('/', function () {
    $user = \App\Models\User::first();
//    return \Illuminate\Support\Facades\Auth::guard('api')->createToken($user)->access_token;
    return \Illuminate\Support\Facades\Auth::guard('api')->user();
});
