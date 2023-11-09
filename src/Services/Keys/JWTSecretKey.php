<?php

namespace Iqbalatma\LaravelJwtAuthentication\Services\Keys;

use Iqbalatma\LaravelJwtAuthentication\Interfaces\JWTKey;

class JWTSecretKey implements JWTKey
{
    /**
     * @return string
     */
    public function getPublicKey(): string
    {
        return config("jwt.secret");
    }

    public function getPrivateKey(): string
    {
        return config("jwt.secret");
    }
}
