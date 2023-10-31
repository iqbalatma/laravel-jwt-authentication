<?php

namespace Iqbalatma\LaravelJwtAuthentication;

use Illuminate\Contracts\Foundation\Application;
use Illuminate\Events\Dispatcher;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\ServiceProvider;
use Iqbalatma\LaravelJwtAuthentication\Console\Commands\JWTGenerateSecretCommand;
use Iqbalatma\LaravelJwtAuthentication\Interfaces\JWTBlacklistService;
use Iqbalatma\LaravelJwtAuthentication\Middleware\Authenticate;

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

        $this->app->singleton(JWTService::class, function () {
            return new JWTService();
        });

        $this->app->bind(JWTBlacklistService::class, function (Application $app) {
            $jwtService = $app->make(JWTService::class);
            return new CacheJWTBlacklistService($jwtService);
        });
    }

    /**
     * Bootstrap services.
     */
    public function boot(): void
    {
        if ($this->app->runningInConsole()){
            $this->commands([
                JWTGenerateSecretCommand::class
            ]);
        }
        /**
         * app is container
         * name is guard name
         * config contain driver-name and provider
         */
        Auth::extend("jwt-iqbal", static function (Application $app, string $name, array $config) {
            $jwtService = $app->make(JWTService::class);
            $userProvider = Auth::createUserProvider($config["provider"]);
            return new JWTGuard($jwtService, $userProvider, $app[Dispatcher::class]);
        });
        Route::aliasMiddleware("auth.jwt", Authenticate::class);
    }
}
