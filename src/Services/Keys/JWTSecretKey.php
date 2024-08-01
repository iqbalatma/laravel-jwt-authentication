<?php

namespace Iqbalatma\LaravelJwtAuthentication\Services\Keys;

use Iqbalatma\LaravelJwtAuthentication\Exceptions\InvalidActionException;
use Iqbalatma\LaravelJwtAuthentication\Exceptions\MissingRequiredAlgorithm;
use Iqbalatma\LaravelJwtAuthentication\Interfaces\JWTKey;
use function PHPUnit\Framework\isEmpty;

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
     * @throws InvalidActionException
     * @throws MissingRequiredAlgorithm
     */
    public function getAlgo(): string
    {
        if (empty($algo = config("jwt.algo"))) {
            throw new MissingRequiredAlgorithm();
        }
        if (!in_array($algo, self::AVAILABLE_ALGO, true)) {
            throw new InvalidActionException("Algorithm $algo is not supported");
        }
        return $algo;
    }
}
