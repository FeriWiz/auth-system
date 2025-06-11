<?php

use App\Http\Controllers\AuthController;
use Illuminate\Support\Facades\Route;

Route::prefix('auth')->group(function () {
    Route::post('signup', [AuthController::class, 'signup']);
    Route::post('login', [AuthController::class, 'login']);

    Route::middleware('jwt.auth')->group(function () {
        Route::post('logout', [AuthController::class, 'logout']);
        Route::get('me', [AuthController::class, 'userInfo']);
        Route::post('refresh', [AuthController::class, 'refresh']); // Changed from GET to POST
    });
});

Route::middleware('jwt.auth')->group(function () {
    Route::get('admin-only', fn() => response()->json(['message' => 'Welcome Admin']))->middleware('role:admin');
    Route::get('amlak-only', fn() => response()->json(['message' => 'Welcome Amlak']))->middleware('role:amlak');
    Route::get('monshi-only', fn() => response()->json(['message' => 'Welcome Monshi']))->middleware('role:monshi');
    Route::get('moshaver-only', fn() => response()->json(['message' => 'Welcome Moshaver']))->middleware('role:moshaver');
});
