<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Tymon\JWTAuth\Facades\JWTAuth;
use Tymon\JWTAuth\Exceptions\JWTException;
use Tymon\JWTAuth\Exceptions\TokenExpiredException;
use Tymon\JWTAuth\Exceptions\TokenInvalidException;

class CheckApiToken
{
    /**
     * Handle an incoming request.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \Closure  $next
     * @return mixed
     */
    public function handle(Request $request, Closure $next)
    {
        try {
            // Check if the token is valid
            if (!$user = JWTAuth::parseToken()->authenticate()) {
                return response()->json([
                    'success' => false,
                    'message' => 'Token is invalid or expired',
                ], 401); // HTTP Status 401 Unauthorized
            }
        } catch (TokenExpiredException $e) {
            // Token has expired
            return response()->json([
                'success' => false,
                'message' => 'Token has expired',
            ], 401); // HTTP Status 401 Unauthorized
        } catch (TokenInvalidException $e) {
            // Token is invalid
            return response()->json([
                'success' => false,
                'message' => 'Token is invalid',
            ], 401); // HTTP Status 401 Unauthorized
        } catch (JWTException $e) {
            // Something went wrong with the token
            return response()->json([
                'success' => false,
                'message' => 'Token is not provided',
            ], 400); // HTTP Status 400 Bad Request
        }

        // Proceed with the request if token is valid
        return $next($request);
    }
}
