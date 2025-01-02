<?php

namespace App\Http\Controllers\API;

use App\Models\User;
use Illuminate\Http\Request;
use App\Http\Controllers\Controller;
use Illuminate\Support\Facades\Validator;
use Tymon\JWTAuth\Facades\JWTAuth;
use Tymon\JWTAuth\Exceptions\JWTException;
use Tymon\JWTAuth\Exceptions\TokenExpiredException;
use Tymon\JWTAuth\Exceptions\TokenInvalidException;

class AuthController extends Controller
{
    // Register a new user
    public function register(Request $request)
    {
        // Set validation rules for the request
        $validator = Validator::make($request->all(), [
            'name'      => 'required',           // Name is required
            'email'     => 'required|email|unique:users', // Email is required, must be unique
            'password'  => 'required|min:5|confirmed'  // Password is required, must have a minimum of 5 characters and confirmed
        ]);

        // If validation fails, return errors
        if ($validator->fails()) {
            return response()->json($validator->errors(), 422);
        }

        // Create a new user
        $user = User::create([
            'name'      => $request->name,
            'email'     => $request->email,
            'password'  => bcrypt($request->password) // Encrypt password
        ]);

        // Return success message if user is created
        if ($user) {
            return response()->json([
                'success' => true,
                'user'    => $user,
            ], 201); // HTTP Status 201 Created
        }

        // Return error message if user creation failed
        return response()->json([
            'success' => false,
        ], 409); // HTTP Status 409 Conflict
    }

    // User login
    public function login(Request $request)
    {
        // Set validation rules for login request
        $validator = Validator::make($request->all(), [
            'email'     => 'required',    // Email is required
            'password'  => 'required'     // Password is required
        ]);

        // If validation fails, return errors
        if ($validator->fails()) {
            return response()->json($validator->errors(), 422);
        }

        // Get the credentials from the request
        $credentials = $request->only('email', 'password');

        // If authentication fails
        if (!$token = auth()->guard('api')->attempt($credentials)) {
            return response()->json([
                'success' => false,
                'message' => 'Invalid email or password' // Error message in English
            ], 401); // HTTP Status 401 Unauthorized
        }

        // If authentication is successful
        return response()->json([
            'success' => true,
            'user'    => auth()->guard('api')->user(),
            'token'   => $token
        ], 200); // HTTP Status 200 OK
    }

    // User logout
    public function logout(Request $request)
    {
        // Invalidate the token
        $removeToken = JWTAuth::invalidate(JWTAuth::getToken());

        // If token invalidation is successful
        if ($removeToken) {
            return response()->json([
                'success' => true,
                'message' => 'Logout successful!', // Success message in English
            ]);
        }
    }
}
