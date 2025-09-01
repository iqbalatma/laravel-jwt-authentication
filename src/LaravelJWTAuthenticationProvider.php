<?php

namespace Iqbalatma\LaravelJwtAuthentication;

use Illuminate\Contracts\Foundation\Application;
use Illuminate\Events\Dispatcher;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\ServiceProvider;
use Iqbalatma\LaravelJwtAuthentication\Console\JWTGenerateCertCommand;
use Iqbalatma\LaravelJwtAuthentication\Console\JWTGenerateSecretCommand;
use Iqbalatma\LaravelJwtAuthentication\Exceptions\JWTKeyNotAvailableException;
use Iqbalatma\LaravelJwtAuthentication\Interfaces\JWTKey;
use Iqbalatma\LaravelJwtAuthentication\Middleware\AuthenticateMiddleware;
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

        #singleton JWTKey that can be used secret key or private/public key
        $this->app->singleton(JWTKey::class, function () {
            if (config("jwt.jwt_public_key") && config("jwt.jwt_private_key")) {
                return new JWTCertKey(config("jwt.jwt_passphrase"));
            }

            if (config("jwt.secret")) {
                return new JWTSecretKey();
            }

            throw new JWTKeyNotAvailableException();
        });

        #singleton JWTService
        $this->app->singleton(JWTService::class, function (Application $app) {
            $jwtKey = $app->make(JWTKey::class);
            return new JWTService($jwtKey);
        });

        #binding blacklist service
        $this->app->bind(Interfaces\JWTBlacklistService::class, function (Application $app) {
            $jwtService = $app->make(JWTService::class);
            return new JWTBlacklistService($jwtService);
        });

        #aliasing middleware
        Route::aliasMiddleware("auth.jwt", AuthenticateMiddleware::class);
    }

    /**
     * Bootstrap services.
     */
    public function boot(): void
    {
        #register command
        if ($this->app->runningInConsole()) {
            $this->commands([
                JWTGenerateSecretCommand::class,
                JWTGenerateCertCommand::class,
            ]);
        }

        /**
         * extending guard
         * app is container
         * name is guard name
         * config contain driver-name and provider
         */
        Auth::extend("jwt", static function (Application $app, string $name, array $config) {
            return new JWTGuard(
                $app->make(JWTService::class),
                Auth::createUserProvider($config["provider"]),
                $app[Dispatcher::class]
            );
        });
    }
}
