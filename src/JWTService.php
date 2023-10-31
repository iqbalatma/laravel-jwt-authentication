<?php

namespace Iqbalatma\LaravelJwtAuthentication;

use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use Illuminate\Contracts\Auth\Authenticatable;
use Iqbalatma\LaravelJwtAuthentication\Abstracts\BaseJWTService;
use Iqbalatma\LaravelJwtAuthentication\Enums\TokenType;
use Iqbalatma\LaravelJwtAuthentication\Exceptions\InvalidActionException;
use Iqbalatma\LaravelJwtAuthentication\Exceptions\ModelNotCompatibleWithJWTSubjectException;
use RuntimeException;
use stdClass;

class JWTService extends BaseJWTService
{
    /**
     * @param Authenticatable $authenticatable
     * @return string
     * @throws InvalidActionException
     * @throws ModelNotCompatibleWithJWTSubjectException
     */
    public function generateAccessToken(Authenticatable $authenticatable): string
    {
        $this->checkAuthenticatableContracts($authenticatable)
            ->setDefaultPayload();


        $payload = array_merge($this->payload, [
            "exp" => $this->payload["exp"] + $this->accessTokenTTL,
            "sub" => $authenticatable->getAuthIdentifier(),
            "type" => TokenType::ACCESS->value,
        ], $authenticatable->getJWTCustomClaims());

        $this->setSubjectCacheRecord($authenticatable->getAuthIdentifier())
            ->executeBlacklistToken(TokenType::ACCESS->value, $this->userAgent);
        return JWT::encode($payload, $this->secretKey, $this->algo);
    }


    /**
     * @param Authenticatable $authenticatable
     * @return string
     * @throws ModelNotCompatibleWithJWTSubjectException|InvalidActionException
     */
    public function generateRefreshToken(Authenticatable $authenticatable): string
    {
        $this->checkAuthenticatableContracts($authenticatable)
            ->setDefaultPayload();

        $payload = array_merge($this->payload, [
            "exp" => $this->payload["exp"] + $this->refreshTTL,
            "sub" => $authenticatable->getAuthIdentifier(),
            "type" => TokenType::REFRESH->value,
        ], $authenticatable->getJWTCustomClaims());

        $this->setSubjectCacheRecord($authenticatable->getAuthIdentifier())
            ->executeBlacklistToken(TokenType::REFRESH->value, $this->userAgent);

        return JWT::encode($payload, $this->secretKey, $this->algo);
    }


    /**
     * @param string $token
     * @return array
     */
    public function decodeJWT(string $token): array
    {
        $headers = new stdClass();
        $this->requestTokenPayloads = (array)JWT::decode($token, new Key($this->secretKey, $this->algo), $headers);

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
