<?php

namespace App\Http\Controllers\Auth;

use App\Http\Requests\LoginRequest;
use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Routing\Controller;
use Illuminate\Support\Facades\Hash;

class AuthController extends Controller
{
    public function login(LoginRequest $request)
    {
        $user = User::where('email', $request->email)->first();

        if (empty($user) || !Hash::check($request->password, $user->password)) {
            return response([
                'message' => 'Login fail'
            ], 401);
        }

        $token = $user->createToken($user->email);

        return response([
            'token_type' => 'Beaer token',
            'token' => $token->plainTextToken,
        ], 200);
    }

    public function logout(Request $request)
    {
        $request->user()->currentAccessToken()->delete();

        return response([
            'message' => 'Logged out',
        ], 200);
    }
}
