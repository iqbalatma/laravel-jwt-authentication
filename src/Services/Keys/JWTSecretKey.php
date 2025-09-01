<?php

namespace Iqbalatma\LaravelJwtAuthentication\Services\Keys;

use Iqbalatma\LaravelJwtAuthentication\Exceptions\JWTInvalidActionException;
use Iqbalatma\LaravelJwtAuthentication\Exceptions\JWTMissingRequiredAlgorithmException;
use Iqbalatma\LaravelJwtAuthentication\Interfaces\JWTKey;

class JWTSecretKey implements JWTKey
{
    private const AVAILABLE_ALGO = [
        "HS512",
        "HS256",
        "HS384",
        "HS224"
    ];

    /**
     * @return string
     */
    public function getPublicKey(): string
    {
        return config("jwt.secret");
    }


    /**
     * @return string
     */
    public function getPrivateKey(): string
    {
        return config("jwt.secret");
    }


    /**
     * @return string
     * @throws JWTInvalidActionException
     * @throws JWTMissingRequiredAlgorithmException
     */
    public function getAlgo(): string
    {
        if (empty($algo = config("jwt.algo"))) {
            throw new JWTMissingRequiredAlgorithmException();
        }
        if (!in_array($algo, self::AVAILABLE_ALGO, true)) {
            throw new JWTInvalidActionException("Algorithm $algo is not supported");
        }
        return $algo;
    }
}
