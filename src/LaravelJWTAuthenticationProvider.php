<?php

namespace Iqbalatma\LaravelJwtAuthentication;

use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Events\Dispatcher;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\ServiceProvider;
use Iqbalatma\LaravelJwtAuthentication\Console\Commands\JWTGenerateCertCommand;
use Iqbalatma\LaravelJwtAuthentication\Console\Commands\JWTGenerateSecretCommand;
use Iqbalatma\LaravelJwtAuthentication\Exceptions\KeyNotAvailableException;
use Iqbalatma\LaravelJwtAuthentication\Interfaces\JWTKey;
use Iqbalatma\LaravelJwtAuthentication\Middleware\Authenticate;
use Iqbalatma\LaravelJwtAuthentication\Services\JWTBlacklistService;
use Iqbalatma\LaravelJwtAuthentication\Services\JWTService;
use Iqbalatma\LaravelJwtAuthentication\Services\Keys\JWTCertKey;
use Iqbalatma\LaravelJwtAuthentication\Services\Keys\JWTSecretKey;

class LaravelJWTAuthenticationProvider extends ServiceProvider
{
    /**
     * Register services.
     */
    public function register(): void
    {
        $this->publishes([
            __DIR__ . "/Config/jwt.php" => config_path("jwt.php")
        ], "config");
        $this->mergeConfigFrom(__DIR__ . '/Config/jwt.php', 'jwt');

        $this->app->singleton(JWTKey::class, function () {
            if (config("jwt.jwt_public_key") && config("jwt.jwt_private_key")) {
                return new JWTCertKey(config("jwt.jwt_passphrase"));
            }

            if (config("jwt.secret")){
                return new JWTSecretKey();
            }

            throw new KeyNotAvailableException();
        });

        $this->app->singleton(JWTService::class, function (Application $app) {
            $jwtKey = $app->make(JWTKey::class);
            return new JWTService($jwtKey);
        });

        $this->app->bind(Interfaces\JWTBlacklistService::class, function (Application $app) {
            $jwtService = $app->make(JWTService::class);
            return new JWTBlacklistService($jwtService);
        });

        Route::aliasMiddleware("auth.jwt", Authenticate::class);
    }

    /**
     * Bootstrap services.
     */
    public function boot(): void
    {
        if ($this->app->runningInConsole()) {
            $this->commands([
                JWTGenerateSecretCommand::class,
                JWTGenerateCertCommand::class,
            ]);
        }
        /**
         * app is container
         * name is guard name
         * config contain driver-name and provider
         */
        Auth::extend("jwt", static function (Application $app, string $name, array $config) {
            $jwtService = $app->make(JWTService::class);
            $userProvider = Auth::createUserProvider($config["provider"]);
            return new JWTGuard($jwtService, $userProvider, $app[Dispatcher::class]);
        });
    }
}
