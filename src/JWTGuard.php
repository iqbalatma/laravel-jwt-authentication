<?php

namespace Iqbalatma\LaravelJwtAuthentication;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Contracts\Events\Dispatcher;
use Iqbalatma\LaravelJwtAuthentication\Abstracts\BaseJWTGuard;

class JWTGuard extends BaseJWTGuard
{

    public function __construct(UserProvider $provider, Dispatcher $events)
    {
        $this->provider = $provider;
        $this->events = $events;
    }

    /**
     * @return Authenticatable|null
     */
    public function user():Authenticatable|null
    {
        if ($this->user !== null) {
            return $this->user;
        }

        return null;
    }

    public function validate(array $credentials = [])
    {
        // TODO: Implement validate() method.
    }


    /**
     * Use to attempt login user using credentials
     * @param array $credentials
     * @return bool
     */
    public function attempt(array $credentials): bool
    {
        $user = $this->provider->retrieveByCredentials($credentials);

        /**
         * todo : fire attempt event
         */

        if ($this->hasValidCredentials($user, $credentials)) {
            return true;
        }

        /**
         * todo: fire attempt failed event
         */
        return false;
    }
}
