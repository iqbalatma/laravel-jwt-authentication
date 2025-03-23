<?php

namespace Iqbalatma\LaravelJwtAuthentication\Services\Keys;

use Iqbalatma\LaravelJwtAuthentication\Contracts\Interfaces\JWTKey;
use Iqbalatma\LaravelJwtAuthentication\Exceptions\JWTInvalidActionException;
use Iqbalatma\LaravelJwtAuthentication\Exceptions\JWTMissingRequiredAlgorithmException;
use OpenSSLAsymmetricKey;

class JWTCertKey implements JWTKey
{
    private const array AVAILABLE_ALGO = [
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
     * @throws JWTInvalidActionException
     * @throws JWTMissingRequiredAlgorithmException
     */
    public function getAlgo(): string
    {
        if (empty($algo = config("jwt.algo"))) {
            throw new JWTMissingRequiredAlgorithmException();
        }
        if (!in_array($algo, self::AVAILABLE_ALGO, true)) {
            throw new JWTInvalidActionException("Algorithm is not supported");
        }
        return $algo;
    }
}
