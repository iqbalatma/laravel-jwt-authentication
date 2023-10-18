<?php

namespace Iqbalatma\LaravelJwtAuthentication\Abstracts;

use Illuminate\Auth\GuardHelpers;
use Illuminate\Contracts\Auth\Guard;
use Illuminate\Contracts\Events\Dispatcher;
use Iqbalatma\LaravelJwtAuthentication\Traits\AuthEventTrait;

abstract class BaseJWTGuard implements Guard
{
    use GuardHelpers, AuthEventTrait;

    protected $name = 'iqbalatma.jwt';

    protected Dispatcher $events;

    /**
     * Used to check is user credential is valid and make sure first param is not null
     * @param $user
     * @param array $credentials
     * @return bool
     */
    protected function hasValidCredentials($user, array $credentials): bool
    {
        $validated = $user !== null && $this->provider->validateCredentials($user, $credentials);
        if ($validated) {
            $this->setUser($user);
            $this->fireValidatedEvent($user);
        }
        return $validated;
    }
}
