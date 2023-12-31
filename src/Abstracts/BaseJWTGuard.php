<?php

namespace Iqbalatma\LaravelJwtAuthentication\Abstracts;

use Illuminate\Auth\GuardHelpers;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\Guard;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Contracts\Events\Dispatcher;
use Iqbalatma\LaravelJwtAuthentication\Services\JWTService;
use Iqbalatma\LaravelJwtAuthentication\Traits\AuthEventTrait;

abstract class BaseJWTGuard implements Guard
{
    use GuardHelpers, AuthEventTrait;
    protected Authenticatable|null $lastAttempted;
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
    protected string|null $refreshToken = null;
}
