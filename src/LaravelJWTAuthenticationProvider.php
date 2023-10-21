<?php

namespace Iqbalatma\LaravelJwtAuthentication;

use Illuminate\Contracts\Container\BindingResolutionException;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\ServiceProvider;

class LaravelJWTAuthenticationProvider extends ServiceProvider
{
    /**
     * Register services.
     */
    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__ . '/Config/jwt_iqbal.php', 'jwt_iqbal');

        $this->app->singleton(JWTService::class, function () {
            return new JWTService();
        });
    }

    /**
     * Bootstrap services.
     */
    public function boot(): void
    {

        $this->publishes([
            __DIR__ . "/Config/jwt_iqbal.php" => config_path("jwt_iqbal.php")
        ], "config");
        /**
         * app is container
         * name is guard name
         * config contain driver-name and provider
         */
        Auth::extend("jwt-iqbal", function (Application $app, string $name, array $config) {
            $jwtService = $app->make(JWTService::class);
            $userProvider = Auth::createUserProvider($config["provider"]);
            return new JWTGuard($jwtService, $userProvider, $app["events"]);
        });
    }
}
