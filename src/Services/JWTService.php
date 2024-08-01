<?php

namespace Iqbalatma\LaravelJwtAuthentication\Services;

use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use Iqbalatma\LaravelJwtAuthentication\Abstracts\BaseJWTService;
use Iqbalatma\LaravelJwtAuthentication\Enums\TokenType;
use Iqbalatma\LaravelJwtAuthentication\Exceptions\InvalidActionException;
use Iqbalatma\LaravelJwtAuthentication\Interfaces\JWTSubject;
use RuntimeException;
use stdClass;

class JWTService extends BaseJWTService
{
    /**
     * @param JWTSubject $authenticatable
     * @return string
     * @throws InvalidActionException
     */
    public function generateAccessToken(JWTSubject $authenticatable): string
    {
        $this->setDefaultPayload();

        $payload = array_merge($this->payload, [
            "exp" => $this->payload["exp"] + $this->accessTokenTTL,
            "sub" => $authenticatable->getAuthIdentifier(),
            "type" => TokenType::ACCESS->value,
        ], $authenticatable->getJWTCustomClaims());

        $this->setIssuedToken($authenticatable->getAuthIdentifier())
            ->blacklistToken(TokenType::ACCESS->value, $this->userAgent, false);

        return JWT::encode($payload, $this->jwtKey->getPrivateKey(), $this->jwtKey->getAlgo());
    }


    /**
     * @param JWTSubject $authenticatable
     * @return string
     * @throws InvalidActionException
     */
    public function generateRefreshToken(JWTSubject $authenticatable): string
    {
        $this->setDefaultPayload();

        $payload = array_merge($this->payload, [
            "exp" => $this->payload["exp"] + $this->refreshTTL,
            "sub" => $authenticatable->getAuthIdentifier(),
            "type" => TokenType::REFRESH->value,
        ], $authenticatable->getJWTCustomClaims());

        $this->setIssuedToken($authenticatable->getAuthIdentifier())
            ->blacklistToken(TokenType::REFRESH->value, $this->userAgent, false);

        return JWT::encode($payload, $this->jwtKey->getPrivateKey(), $this->jwtKey->getAlgo());
    }


    /**
     * @param string $token
     * @return array
     */
    public function decodeJWT(string $token): array
    {
        $headers = new stdClass();
        $this->requestTokenPayloads = (array)JWT::decode($token, new Key($this->jwtKey->getPublicKey(), $this->jwtKey->getAlgo()), $headers);

        $this->requestTokenHeaders = $headers;
        return $this->requestTokenPayloads;
    }


    /**
     * @param string|null $key
     * @return string|array
     */
    public function getRequestedTokenPayloads(null|string $key = null): string|array
    {
        if ($key) {
            if (isset($this->requestTokenPayloads[$key])) {
                return $this->requestTokenPayloads[$key];
            }

            throw new RuntimeException("Undefined array key $key");
        }

        return $this->requestTokenPayloads;
    }


    /**
     * @param string|null $key
     * @return string|array
     */
    public function getRequestTokenHeaders(null|string $key = null): string|array
    {
        $headers = (array)$this->requestTokenHeaders;
        if ($key) {
            if (isset($headers[$key])) {
                return $headers[$key];
            }

            throw new RuntimeException("Undefined array key $key");
        }
        return $headers;
    }
}
