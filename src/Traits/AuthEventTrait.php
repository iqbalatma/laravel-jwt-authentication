<?php

namespace Iqbalatma\LaravelJwtAuthentication\Traits;

use Illuminate\Auth\Events\Attempting;
use Illuminate\Auth\Events\Authenticated;
use Illuminate\Auth\Events\Failed;
use Illuminate\Auth\Events\Login;
use Illuminate\Auth\Events\Logout;
use Illuminate\Contracts\Auth\Authenticatable;
use Iqbalatma\LaravelJwtAuthentication\JWTGuard;
use Illuminate\Auth\Events\Validated;

/**
 * @mixin JWTGuard
 */
trait AuthEventTrait
{
    /**
     * This use when user credentials is validated
     * @param $user
     * @return void
     */
    protected function fireValidatedEvent($user): void
    {
        if (class_exists(Validated::class)) {
            $this->events->dispatch(
                new Validated(
                    $this->name,
                    $user
                )
            );
        }
    }

    /**
     * Fire the attempt event.
     *
     * @param array $credentials
     * @return void
     */
    protected function fireAttemptEvent(array $credentials): void
    {
        $this->events->dispatch(new Attempting(
            $this->name,
            $credentials,
            false
        ));
    }

    /**
     * Fire the failed authentication attempt event.
     *
     * @param Authenticatable|null $user
     * @param array $credentials
     * @return void
     */
    protected function fireFailedEvent(?Authenticatable $user, array $credentials): void
    {
        $this->events->dispatch(new Failed(
            $this->name,
            $user,
            $credentials
        ));
    }

    /**
     * Fire when user success authenticated
     *
     * @param $user
     * @return void
     */
    protected function fireAuthenticatedEvent($user): void
    {
        $this->events->dispatch(new Authenticated(
            $this->name,
            $user
        ));
    }

    /**
     * Fire the login event.
     *
     * @param Authenticatable $user
     * @param bool $remember
     *
     * @return void
     */
    protected function fireLoginEvent(Authenticatable $user, bool $remember = false): void
    {
        $this->events->dispatch(new Login(
            $this->name,
            $user,
            $remember
        ));
    }

    /**
     * Fire the logout event.
     *
     * @param Authenticatable $user
     * @param bool $remember
     *
     * @return void
     */
    protected function fireLogoutEvent(Authenticatable $user, bool $remember = false): void
    {
        $this->events->dispatch(new Logout(
            $this->name,
            $user
        ));
    }
}
