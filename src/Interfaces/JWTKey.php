<?php

namespace Iqbalatma\LaravelJwtAuthentication\Interfaces;

interface JWTKey
{
    /**
     * @return string
     */
    public function getPublicKey():string;

    /**
     * @return string
     */
    public function getPrivateKey():string;
}
