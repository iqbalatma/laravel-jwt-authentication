<?php

namespace Iqbalatma\LaravelJwtAuthentication\Services;

use Iqbalatma\LaravelJwtAuthentication\Interfaces\JWTKey;

abstract class BaseJWTService
{
    public int $accessTokenTTL;
    public int $refreshTokenTTL;
    public function __construct(protected JWTKey $jwtKey)
    {
        $this->accessTokenTTL = config("jwt.access_token_ttl");
        $this->refreshTokenTTL = config("jwt.refresh_token_ttl");
    }
}
