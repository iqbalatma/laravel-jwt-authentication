<?php

namespace Iqbalatma\LaravelJwtAuthentication\Services\Keys;

use Iqbalatma\LaravelJwtAuthentication\Interfaces\JWTKey;

class JWTCertKey implements JWTKey
{
    /**
     * @return string
     */
    public function getPublicKey(): string
    {
        return file_get_contents(storage_path(config("jwt.jwt_public_key")));
    }

    /**
     * @return string
     */
    public function getPrivateKey(): string
    {
        return file_get_contents(storage_path(config("jwt.jwt_private_key")));
    }
}
