<?php

namespace Iqbalatma\LaravelJwtAuthentication\Abstracts;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Str;
use Iqbalatma\LaravelJwtAuthentication\Exceptions\MissingRequiredHeaderException;
use Iqbalatma\LaravelJwtAuthentication\Exceptions\ModelNotCompatibleWithJWTSubjectException;
use Iqbalatma\LaravelJwtAuthentication\Interfaces\JWTSubject;
use Iqbalatma\LaravelJwtAuthentication\JWTService;
use Iqbalatma\LaravelJwtAuthentication\Traits\IssuedTokenHelper;
use stdClass;

abstract class BaseJWTService
{
    use IssuedTokenHelper;

    protected string $secretKey;
    protected string $algo;
    protected string|null $userAgent;
    protected int $accessTokenTTL;
    protected int $refreshTTL;
    protected array $payload;
    protected array $requestTokenPayloads;
    protected stdClass $requestTokenHeaders;

    /**
     * @throws MissingRequiredHeaderException
     */
    public function __construct()
    {
        $this->secretKey = config("jwt.secret");
        $this->algo = config("jwt.algo");
        $this->accessTokenTTL = config("jwt.access_token_ttl");
        $this->refreshTTL = config("jwt.refresh_token_ttl");
        $this->userAgent = request()->userAgent();
        if (!$this->userAgent) {
            throw new MissingRequiredHeaderException("Missing required header User-Agent");
        }
    }

    protected function setDefaultPayload(): void
    {
        $now = time();
        if (!Cache::get(config("jwt.latest_incident_time_key"))) {
            Cache::forever(config("jwt.latest_incident_time_key"), $now - 1);
        }
        $this->payload = [
            'iss' => url()->current(),
            'iat' => $now,
            'exp' => $now,
            'nbf' => $now,
            'jti' => Str::random(),
            'sub' => null,
            'iua' => $this->userAgent
        ];
    }

    /**
     * @param Authenticatable $authenticatable
     * @return JWTService
     * @throws ModelNotCompatibleWithJWTSubjectException
     */
    protected function checkAuthenticatableContracts(Authenticatable $authenticatable): self
    {
        if (!$authenticatable instanceof JWTSubject) {
            throw new ModelNotCompatibleWithJWTSubjectException();
        }

        return $this;
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
    public function getRequestedIua(): string
    {
        return $this->getRequestedTokenPayloads("iua");
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
    public function getRequestedType(): string
    {
        return $this->getRequestedTokenPayloads("type");
    }


    /**
     * @return string
     */
    public function getRequestedExp(): string
    {
        return $this->getRequestedTokenPayloads("exp");
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
