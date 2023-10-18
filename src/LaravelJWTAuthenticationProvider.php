<?php

namespace Iqbalatma\LaravelJwtAuthentication;

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
        $this->app->alias("iqbalatma.jwt", JWT::class);
    }

    /**
     * Bootstrap services.
     */
    public function boot(): void
    {
        /**
         * app is container
         * name is guard name
         * config contain driver-name and provider
         */
        Auth::extend("jwt-iqbal", function (Application $app, string $name, array $config) {
            $userProvider = Auth::createUserProvider($config["provider"]);
            return new JWTGuard($userProvider, $app["events"]);
        });
    }
}
