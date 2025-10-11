<?php

namespace Iqbalatma\LaravelJwtAuthentication\Services;

use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use Iqbalatma\LaravelJwtAuthentication\Payload;
use RuntimeException;
use stdClass;

class DecodingService extends BaseJWTService
{
    protected Payload $payload;
    protected array $requestTokenPayloads;
    protected stdClass $requestTokenHeaders;

    /**
     * @param string $token
     * @return array
     */
    public function decodeJWT(string $token): array
    {
        $headers = new stdClass();
        $this->requestTokenPayloads = (array)JWT::decode(
            $token,
            new Key($this->jwtKey->getPublicKey(), $this->jwtKey->getAlgo()),
            $headers
        );
        $this->requestTokenHeaders = $headers;

        return $this->requestTokenPayloads;
    }


    /**
     * @param string|null $key
     * @return string|array
     */
    public function getRequestedTokenPayloads(null|string $key = null): string|array
    {
        if (!isset($this->requestTokenPayloads)) {
            throw new RuntimeException("Token payloads are not set.");
        }

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


    /**
     * @return string
     */
    public function getRequestedIss(): string
    {
        return $this->getRequestedTokenPayloads("iss");
    }


    /**
     * @return string
     */
    public function getRequestedIat(): string
    {
        return $this->getRequestedTokenPayloads("iat");
    }

    /**
     * @return string
     */
    public function getRequestedExp(): string
    {
        return $this->getRequestedTokenPayloads("exp");
    }

    /**
     * @return string
     */
    public function getRequestedNbf(): string
    {
        return $this->getRequestedTokenPayloads("nbf");
    }

    /**
     * @return string
     */
    public function getRequestedJti(): string
    {
        return $this->getRequestedTokenPayloads("jti");
    }


    /**
     * @return string
     */
    public function getRequestedSub(): string
    {
        return $this->getRequestedTokenPayloads("sub");
    }


    /**
     * @return string
     */
    public function getRequestedIua(): string
    {
        return $this->getRequestedTokenPayloads("iua");
    }

    /**
     * @return string
     */
    public function getRequestedAtv(): string
    {
        return $this->getRequestedTokenPayloads("atv");
    }


    /**
     * @return string
     */
    public function getRequestedType(): string
    {
        return $this->getRequestedTokenPayloads("type");
    }

    /**
     * @return bool
     */
    public function getIsUsingCookie(): bool
    {
        return $this->getRequestedTokenPayloads("iuc");
    }

    /**
     * @return string
     */
    public function getRequestedPti(): string
    {
        return $this->getRequestedTokenPayloads("pti");
    }
}
