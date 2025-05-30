<?php

namespace Iqbalatma\LaravelJwtAuthentication\Contracts\Interfaces;

use OpenSSLAsymmetricKey;

interface JWTKey
{
    /**
     * @return string
     */
    public function getPublicKey(): string;

    /**
     * @return string|bool|OpenSSLAsymmetricKey
     */
    public function getPrivateKey(): string|bool|OpenSSLAsymmetricKey;

    /**
     * @return string
     */
    public function getAlgo():string;
}
