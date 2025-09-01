<?php

namespace Iqbalatma\LaravelJwtAuthentication\Interfaces;

interface JWTSubject
{
    /**
     * Get the identifier that will be stored in the subject claim of the JWT.
     *
     * @return string|int
     */
    public function getJWTIdentifier(): string|int;

    /**
     * Return a key value array, containing any custom claims to be added to the JWT.
     *
     * @return array
     */
    public function getJWTCustomClaims(): array;
}
