<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Response;
use Tymon\JWTAuth\Facades\JWTAuth;

class RoleMiddleware
{
    public function handle($request, Closure $next, ...$roles)
    {
        $user = JWTAuth::user();

        if (!in_array($user->role, $roles)) {
            return response()->json([
                'error' => 'You do not have permission to access this page. ',
                'data' => []
            ], Response::HTTP_UNAUTHORIZED);
        }

        return $next($request);
    }
}
