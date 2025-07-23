<?php

namespace Iqbalatma\LaravelJwtAuthentication\Contracts\Abstracts;

use Illuminate\Support\Str;
use Iqbalatma\LaravelJwtAuthentication\Contracts\Interfaces\JWTKey;
use Iqbalatma\LaravelJwtAuthentication\Exceptions\JWTMissingRequiredHeaderException;
use Iqbalatma\LaravelJwtAuthentication\Services\IncidentTimeService;
use stdClass;

abstract class BaseJWTService
{

    protected string $userAgent;
    protected int $accessTokenTTL;
    protected int $refreshTokenTTL;
    protected array $payload;
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
     * @return BaseJWTService
     */
    protected function setDefaultPayload(): self
    {
        $now = time();
        IncidentTimeService::check();

        $this->payload = [
            'iss' => url()->current(), #issuer : the one who issue this token
            'iat' => $now, #issued at : epoch time when this token is issued
            'exp' => $now, #expired at : epoch time when this token is expired, cannot use anymore
            'nbf' => $now, #not valid before : epoch time when this token is start to valid
            'jti' => Str::uuid(), #json token identifier : this is unique identifier to this token
            'sub' => null, #subject : who is the owner of this token
            'iua' => $this->userAgent, #issued user agent : user agent that call this token to issued,
        ];

        return $this;
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
