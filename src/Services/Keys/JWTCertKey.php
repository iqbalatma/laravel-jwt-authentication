<?php

namespace Iqbalatma\LaravelJwtAuthentication\Services\Keys;

use Iqbalatma\LaravelJwtAuthentication\Exceptions\InvalidActionException;
use Iqbalatma\LaravelJwtAuthentication\Exceptions\MissingRequiredAlgorithm;
use Iqbalatma\LaravelJwtAuthentication\Interfaces\JWTKey;
use OpenSSLAsymmetricKey;

class JWTCertKey implements JWTKey
{
    private const AVAILABLE_ALGO = [
        "RS512",
        "RS256",
        "RS384",
        "ES384",
        "ES256",
        "ES256K"
    ];

    public function __construct(protected string|null $passPhrase)
    {
    }


    /**
     * @return string
     */
    public function getPublicKey(): string
    {
        return file_get_contents(base_path(config("jwt.jwt_public_key")));
    }


    /**
     * @return string|bool|OpenSSLAsymmetricKey
     */
    public function getPrivateKey(): string|bool|OpenSSLAsymmetricKey
    {
        if (is_null($this->passPhrase) || $this->passPhrase === "") {
            return file_get_contents(base_path(config("jwt.jwt_private_key")));
        }

        return openssl_pkey_get_private(
            file_get_contents(base_path(config("jwt.jwt_private_key"))),
            $this->passPhrase
        );
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
            throw new InvalidActionException("Algorithm is not supported");
        }
        return $algo;
    }
}
