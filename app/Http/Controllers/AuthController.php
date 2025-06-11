<?php

namespace App\Http\Controllers;

use App\Http\Requests\SignUpRequest;
use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Illuminate\Support\Facades\Hash;
use Tymon\JWTAuth\Facades\JWTAuth;
use Tymon\JWTAuth\Exceptions\JWTException;
use OpenApi\Annotations as OA;

class AuthController extends Controller
{
    /**
     * @OA\Post(
     *     path="/api/auth/signup",
     *     tags={"Authentication"},
     *     summary="Register a new user",
     *     description="Creates a new user account and returns a JWT token",
     *     @OA\RequestBody(
     *         required=true,
     *         @OA\JsonContent(
     *             @OA\Property(property="name", type="string", example="Farbod Haghighi", description="User's full name", maxLength=255),
     *             @OA\Property(property="email", type="string", format="email", example="fericom3930@gmail.com", description="User's email address", maxLength=255),
     *             @OA\Property(property="password", type="string", example="password123", description="User's password (minimum 8 characters)", minLength=8),
     *             @OA\Property(property="role", type="string", example="moshaver", description="User's role", enum={"admin", "amlak", "monshi", "moshaver"})
     *         )
     *     ),
     *     @OA\Response(
     *         response=201,
     *         description="User created successfully",
     *         @OA\JsonContent(
     *             @OA\Property(property="access_token", type="string", example="eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ5..."),
     *             @OA\Property(property="refresh_token", type="string", example="eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9..."),
     *             @OA\Property(property="token_type", type="string", example="bearer"),
     *             @OA\Property(property="expires_in", type="integer", example=900),
     *             @OA\Property(property="refresh_expires_in", type="integer", example=604800),
     *             @OA\Property(
     *                 property="user",
     *                 type="object",
     *                 @OA\Property(property="id", type="integer", example=1),
     *                 @OA\Property(property="name", type="string", example="Farbod Haghighi"),
     *                 @OA\Property(property="email", type="string", example="fericom3930@gmail.com"),
     *                 @OA\Property(property="role", type="string", example="moshaver"),
     *                 @OA\Property(property="created_at", type="string", format="date-time", example="2025-06-10T22:44:00.000000Z"),
     *                 @OA\Property(property="updated_at", type="string", format="date-time", example="2025-06-10T22:44:00.000000Z")
     *             )
     *         )
     *     ),
     *     @OA\Response(
     *         response=422,
     *         description="Validation error",
     *         @OA\JsonContent(
     *             @OA\Property(property="message", type="string", example="The email field is required."),
     *             @OA\Property(
     *                 property="errors",
     *                 type="object",
     *                 @OA\Property(
     *                     property="email",
     *                     type="array",
     *                     @OA\Items(type="string", example="The email field is required.")
     *                 )
     *             )
     *         )
     *     ),
     *     @OA\Response(
     *         response=500,
     *         description="Server error",
     *         @OA\JsonContent(
     *             @OA\Property(property="error", type="string", example="Could not create token"),
     *             @OA\Property(property="details", type="string", example="Token generation failed")
     *         )
     *     )
     * )
     */
    public function signup(SignUpRequest $request)
    {
        $user = User::create([
            'name' => $request->input('name'),
            'email' => $request->input('email'),
            'password' => Hash::make($request->input('password')),
            'role' => $request->input('role'),
        ]);

        try {
            // Generate access token
            $accessToken = JWTAuth::fromUser($user);

            // Generate refresh token with longer TTL
            $refreshToken = auth()->setTTL(config('jwt.refresh_ttl'))->fromUser($user);

            return response()->json([
                'access_token' => $accessToken,
                'refresh_token' => $refreshToken,
                'token_type' => 'bearer',
                'expires_in' => config('jwt.ttl') * 60,
                'refresh_expires_in' => config('jwt.refresh_ttl') * 60,
                'user' => $user,
            ], 201);
        } catch (JWTException $e) {
            return response()->json([
                'error' => 'Could not create token',
                'details' => $e->getMessage(),
            ], 500);
        }
    }

    /**
     * @OA\Post(
     *     path="/api/auth/login",
     *     tags={"Authentication"},
     *     summary="Authenticate a user",
     *     description="Logs in a user with email and password, returning JWT access and refresh tokens",
     *     @OA\RequestBody(
     *         required=true,
     *         @OA\JsonContent(
     *             @OA\Property(property="email", type="string", format="email", example="fericom3930@gmail.com", description="User's email address"),
     *             @OA\Property(property="password", type="string", example="password123", description="User's password")
     *         )
     *     ),
     *     @OA\Response(
     *         response=200,
     *         description="Login successful",
     *         @OA\JsonContent(
     *             @OA\Property(property="access_token", type="string", example="eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9..."),
     *             @OA\Property(property="refresh_token", type="string", example="eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9..."),
     *             @OA\Property(property="token_type", type="string", example="bearer"),
     *             @OA\Property(property="expires_in", type="integer", example=900),
     *             @OA\Property(property="refresh_expires_in", type="integer", example=604800)
     *         )
     *     ),
     *     @OA\Response(
     *         response=401,
     *         description="Invalid credentials",
     *         @OA\JsonContent(
     *             @OA\Property(property="error", type="string", example="Invalid credentials"),
     *             @OA\Property(property="data", type="array", @OA\Items(type="string"))
     *         )
     *     ),
     *     @OA\Response(
     *         response=422,
     *         description="Validation error",
     *         @OA\JsonContent(
     *             @OA\Property(property="message", type="string", example="The email field is required."),
     *             @OA\Property(
     *                 property="errors",
     *                 type="object",
     *                 @OA\Property(
     *                     property="email",
     *                     type="array",
     *                     @OA\Items(type="string", example="The email field is required.")
     *                 )
     *             )
     *         )
     *     ),
     *     @OA\Response(
     *         response=500,
     *         description="Server error",
     *         @OA\JsonContent(
     *             @OA\Property(property="error", type="string", example="Could not create token"),
     *             @OA\Property(property="details", type="string", example="Token generation failed"),
     *             @OA\Property(property="data", type="array", @OA\Items(type="string"))
     *         )
     *     )
     * )
     */
    public function login(Request $request)
    {
        // Add validation for login
        $request->validate([
            'email' => 'required|email',
            'password' => 'required|string|min:8',
        ]);

        $credentials = $request->only('email', 'password');

        try {
            if (!$token = auth()->attempt($credentials)) {
                return response()->json([
                    'error' => 'Invalid credentials',
                    'data' => []
                ], Response::HTTP_UNAUTHORIZED);
            }
        } catch (JWTException $e) {
            return response()->json([
                'error' => 'Could not create token',
                'details' => $e->getMessage(),
                'data' => []
            ], Response::HTTP_INTERNAL_SERVER_ERROR);
        }

        // Generate refresh token with user instance
        $user = auth()->user();
        $refreshToken = auth()->setTTL(config('jwt.refresh_ttl'))->fromUser($user);

        return response()->json([
            'access_token' => $token,
            'refresh_token' => $refreshToken,
            'token_type' => 'bearer',
            'expires_in' => config('jwt.ttl') * 60,
            'refresh_expires_in' => config('jwt.refresh_ttl') * 60,
        ]);
    }

    /**
     * @OA\Post(
     *     path="/api/auth/logout",
     *     tags={"Authentication"},
     *     summary="Logout a user",
     *     description="Invalidates the user's access and refresh tokens to log them out",
     *     @OA\RequestBody(
     *         required=true,
     *         @OA\JsonContent(
     *             @OA\Property(property="refresh_token", type="string", example="eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...", description="The refresh token obtained during login")
     *         )
     *     ),
     *     @OA\Parameter(
     *         name="Authorization",
     *         in="header",
     *         required=true,
     *         description="JWT access token (e.g., 'Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...')",
     *         @OA\Schema(type="string")
     *     ),
     *     @OA\Response(
     *         response=200,
     *         description="Logout successful",
     *         @OA\JsonContent(
     *             @OA\Property(property="message", type="string", example="Successfully logged out"),
     *             @OA\Property(property="data", type="array", @OA\Items(type="string"))
     *         )
     *     ),
     *     @OA\Response(
     *         response=422,
     *         description="Validation error",
     *         @OA\JsonContent(
     *             @OA\Property(property="message", type="string", example="The refresh token field is required."),
     *             @OA\Property(
     *                 property="errors",
     *                 type="object",
     *                 @OA\Property(
     *                     property="refresh_token",
     *                     type="array",
     *                     @OA\Items(type="string", example="The refresh token field is required.")
     *                 )
     *             )
     *         )
     *     ),
     *     @OA\Response(
     *         response=401,
     *         description="Unauthorized",
     *         @OA\JsonContent(
     *             @OA\Property(property="message", type="string", example="Token not provided"),
     *             @OA\Property(property="exception", type="string", example="Symfony\\Component\\HttpKernel\\Exception\\UnauthorizedHttpException")
     *         )
     *     ),
     *     @OA\Response(
     *         response=500,
     *         description="Server error",
     *         @OA\JsonContent(
     *             @OA\Property(property="error", type="string", example="Could not invalidate token"),
     *             @OA\Property(property="details", type="string", example="Token invalidation failed")
     *         )
     *     )
     * )
     */
    public function logout(Request $request)
    {
        $request->validate(['refresh_token' => 'required|string']);
        $refreshToken = $request->input('refresh_token');

        try {
            // Invalidate access token
            JWTAuth::invalidate(JWTAuth::getToken());

            // Invalidate refresh token
            JWTAuth::setToken($refreshToken)->invalidate();

            return response()->json([
                'message' => 'Successfully logged out',
                'data' => []
            ], Response::HTTP_OK);
        } catch (JWTException $e) {
            return response()->json([
                'error' => 'Could not invalidate token',
                'details' => $e->getMessage()
            ], Response::HTTP_INTERNAL_SERVER_ERROR);
        }
    }

    /**
     * @OA\Get(
     *     path="/api/auth/me",
     *     tags={"Authentication"},
     *     summary="Get authenticated user information",
     *     description="Returns the details of the currently authenticated user",
     *     @OA\Parameter(
     *         name="Authorization",
     *         in="header",
     *         required=true,
     *         description="JWT access token (e.g., 'Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...')",
     *         @OA\Schema(type="string")
     *     ),
     *     @OA\Response(
     *         response=200,
     *         description="User information retrieved successfully",
     *         @OA\JsonContent(
     *             @OA\Property(property="id", type="integer", example=1),
     *             @OA\Property(property="name", type="string", example="Farbod Haghighi"),
     *             @OA\Property(property="email", type="string", example="fericom3930@gmail.com"),
     *             @OA\Property(property="role", type="string", example="moshaver"),
     *             @OA\Property(property="created_at", type="string", format="date-time", example="2025-06-11T09:49:00.000000Z"),
     *             @OA\Property(property="updated_at", type="string", format="date-time", example="2025-06-11T09:49:00.000000Z")
     *         )
     *     ),
     *     @OA\Response(
     *         response=404,
     *         description="User not found",
     *         @OA\JsonContent(
     *             @OA\Property(property="error", type="string", example="User not found"),
     *             @OA\Property(property="data", type="array", @OA\Items(type="string"))
     *         )
     *     ),
     *     @OA\Response(
     *         response=401,
     *         description="Unauthorized",
     *         @OA\JsonContent(
     *             @OA\Property(property="message", type="string", example="Token not provided"),
     *             @OA\Property(property="exception", type="string", example="Symfony\\Component\\HttpKernel\\Exception\\UnauthorizedHttpException")
     *         )
     *     ),
     *     @OA\Response(
     *         response=500,
     *         description="Server error",
     *         @OA\JsonContent(
     *             @OA\Property(property="error", type="string", example="Failed to fetch user profile"),
     *             @OA\Property(property="details", type="string", example="Token is invalid"),
     *             @OA\Property(property="data", type="array", @OA\Items(type="string"))
     *         )
     *     )
     * )
     */
    public function userInfo()
    {
        try {
            // Ensure the user is authenticated through JWT token
            $user = auth()->user();

            if (!$user) {
                return response()->json([
                    'error' => 'User not found',
                    'data' => []
                ], Response::HTTP_NOT_FOUND);
            }

            // Return user information in a structured format
            return response()->json([
                'id' => $user->id,
                'name' => $user->name,
                'email' => $user->email,
                'role' => $user->role,
                'created_at' => $user->created_at->toIso8601String(),
                'updated_at' => $user->updated_at->toIso8601String(),
            ], Response::HTTP_OK);

        } catch (JWTException $e) {
            return response()->json([
                'error' => 'Failed to fetch user profile',
                'details' => $e->getMessage(),
                'data' => []
            ], Response::HTTP_INTERNAL_SERVER_ERROR);
        }
    }

    /**
     * @OA\Post(
     *     path="/api/auth/refresh",
     *     tags={"Authentication"},
     *     summary="Refresh JWT token",
     *     description="Refreshes the access token using the refresh token",
     *     @OA\Parameter(
     *         name="Authorization",
     *         in="header",
     *         required=true,
     *         description="JWT refresh token (e.g., 'Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...')",
     *         @OA\Schema(type="string")
     *     ),
     *     @OA\Response(
     *         response=200,
     *         description="Token refreshed successfully",
     *         @OA\JsonContent(
     *             @OA\Property(property="access_token", type="string", example="eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9..."),
     *             @OA\Property(property="token_type", type="string", example="bearer"),
     *             @OA\Property(property="expires_in", type="integer", example=900)
     *         )
     *     ),
     *     @OA\Response(
     *         response=401,
     *         description="Unauthorized",
     *         @OA\JsonContent(
     *             @OA\Property(property="error", type="string", example="Token is invalid or expired"),
     *             @OA\Property(property="data", type="array", @OA\Items(type="string"))
     *         )
     *     ),
     *     @OA\Response(
     *         response=500,
     *         description="Server error",
     *         @OA\JsonContent(
     *             @OA\Property(property="error", type="string", example="Could not refresh token"),
     *             @OA\Property(property="details", type="string", example="Token refresh failed"),
     *             @OA\Property(property="data", type="array", @OA\Items(type="string"))
     *         )
     *     )
     * )
     */
    public function refresh()
    {
        try {
            $newToken = auth()->refresh();
            return response()->json([
                'access_token' => $newToken,
                'token_type' => 'bearer',
                'expires_in' => config('jwt.ttl') * 60,
            ]);
        } catch (JWTException $e) {
            return response()->json([
                'error' => 'Could not refresh token',
                'details' => $e->getMessage(),
                'data' => []
            ], Response::HTTP_INTERNAL_SERVER_ERROR);
        }
    }
}
