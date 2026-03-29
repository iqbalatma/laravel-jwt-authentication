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
    public function getRequestedTokenPayloads(null|string $key = null): string|array|null
    {
        if (!isset($this->requestTokenPayloads)) {
            $this->requestTokenPayloads = [];
        }

        if ($key) {
            return $this->requestTokenPayloads[$key] ?? null;
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
     * @param array $payloads
     * @return $this
     */
    public function setRequestedTokenPayloads(array $payloads): self
    {
        $this->requestTokenPayloads = $payloads;
        return $this;
    }

    /**
     * @param stdClass $headers
     * @return $this
     */
    public function setRequestedTokenHeaders(stdClass $headers): self
    {
        $this->requestTokenHeaders = $headers;
        return $this;
    }


    /**
     * @return string|null
     */
    public function getRequestedIss(): string|null
    {
        return $this->getRequestedTokenPayloads("iss");
    }


    /**
     * @return  string|null
     */
    public function getRequestedIat(): string|null
    {
        return $this->getRequestedTokenPayloads("iat");
    }

    /**
     * @return  string|null
     */
    public function getRequestedExp(): string|null
    {
        return $this->getRequestedTokenPayloads("exp");
    }

    /**
     * @return  string|null
     */
    public function getRequestedNbf(): string|null
    {
        return $this->getRequestedTokenPayloads("nbf");
    }

    /**
     * @return  string|null
     */
    public function getRequestedJti(): string|null
    {
        return $this->getRequestedTokenPayloads("jti");
    }


    /**
     * @return  string|null
     */
    public function getRequestedSub(): string|null
    {
        return $this->getRequestedTokenPayloads("sub");
    }


    /**
     * @return  string|null
     */
    public function getRequestedIua(): string|null
    {
        return $this->getRequestedTokenPayloads("iua");
    }

    /**
     * @return  string|null
     */
    public function getRequestedAtv(): string|null
    {
        return $this->getRequestedTokenPayloads("atv");
    }


    /**
     * @return  string|null
     */
    public function getRequestedType(): string|null
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
     * @return  string|null
     */
    public function getRequestedPti(): string|null
    {
        return $this->getRequestedTokenPayloads("pti");
    }
}
