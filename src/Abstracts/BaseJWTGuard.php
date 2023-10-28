<?php

namespace Iqbalatma\LaravelJwtAuthentication\Abstracts;

use Illuminate\Auth\GuardHelpers;
use Illuminate\Contracts\Auth\Guard;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Contracts\Events\Dispatcher;
use Iqbalatma\LaravelJwtAuthentication\JWTService;
use Iqbalatma\LaravelJwtAuthentication\Traits\AuthEventTrait;

abstract class BaseJWTGuard implements Guard
{
    use GuardHelpers, AuthEventTrait;

    public function __construct(JWTService $jwtService, UserProvider $provider, Dispatcher $events)
    {
        $this->jwtService = $jwtService;
        $this->provider = $provider;
        $this->events = $events;
    }

    protected $name = 'iqbalatma.jwt';

    protected Dispatcher $events;
    protected JWTService $jwtService;
    protected string|null $accessToken = null;
    protected string|null $refreshToken=null;

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
