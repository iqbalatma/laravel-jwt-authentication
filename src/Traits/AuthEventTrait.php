<?php

namespace Iqbalatma\LaravelJwtAuthentication\Traits;

use Iqbalatma\LaravelJwtAuthentication\JWTGuard;

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
        if (class_exists('Illuminate\Auth\Events\Validated')) {
            $this->events->dispatch(
                new \Illuminate\Auth\Events\Validated(
                    $this->name,
                    $user
                )
            );
        }
    }
}
