<?php

namespace Iqbalatma\LaravelJwtAuthentication\Abstracts;

use Illuminate\Support\Str;
use Iqbalatma\LaravelJwtAuthentication\Exceptions\JWTMissingRequiredHeaderException;
use Iqbalatma\LaravelJwtAuthentication\Interfaces\JWTKey;
use Iqbalatma\LaravelJwtAuthentication\Payload;
use Iqbalatma\LaravelJwtAuthentication\Services\IncidentTimeService;
use stdClass;

abstract class BaseJWTService
{

    protected string $userAgent;
    protected int $accessTokenTTL;
    protected int $refreshTokenTTL;
    protected Payload $payload;
    protected array $requestTokenPayloads;
    protected stdClass $requestTokenHeaders;

    /**
     * @throws JWTMissingRequiredHeaderException
     */
    public function __construct(protected JWTKey $jwtKey)
    {
        $this->accessTokenTTL = config("jwt.access_token_ttl");
        $this->refreshTokenTTL = config("jwt.refresh_token_ttl");
        if (!($userAgent = request()?->userAgent())) {
            throw new JWTMissingRequiredHeaderException("Your request is missing user-agent required header");
        }
        $this->userAgent = $userAgent;
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

    public function getIsUsingCookie(): bool
    {
        return $this->getRequestedTokenPayloads("iuc");
    }

    /**
     * @param string|null $key
     * @return string|array
     */
    abstract public function getRequestedTokenPayloads(null|string $key = null): string|array;

    /**
     * @param string|null $key
     * @return string|array
     */
    abstract public function getRequestTokenHeaders(null|string $key = null): string|array;
}
