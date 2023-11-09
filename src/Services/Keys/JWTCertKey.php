<?php

namespace Iqbalatma\LaravelJwtAuthentication\Services\Keys;

use Iqbalatma\LaravelJwtAuthentication\Interfaces\JWTKey;
use OpenSSLAsymmetricKey;

class JWTCertKey implements JWTKey
{
    public function __construct(protected string|null $passPhrase)
    {
    }

    /**
     * @return string
     */
    public function getPublicKey(): string
    {
        return file_get_contents(storage_path(config("jwt.jwt_public_key")));
    }

    /**
     * @return string|bool|OpenSSLAsymmetricKey
     */
    public function getPrivateKey(): string|bool|OpenSSLAsymmetricKey
    {
        if (is_null($this->passPhrase) || $this->passPhrase === "") {
            return file_get_contents(storage_path(config("jwt.jwt_private_key")));
        }

        return openssl_pkey_get_private(
            file_get_contents(storage_path(config("jwt.jwt_private_key"))),
            $this->passPhrase
        );
    }
}
