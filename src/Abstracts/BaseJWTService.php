<?php

namespace Iqbalatma\LaravelJwtAuthentication\Abstracts;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Str;
use Iqbalatma\LaravelJwtAuthentication\Exceptions\MissingRequiredHeaderException;
use Iqbalatma\LaravelJwtAuthentication\Exceptions\ModelNotCompatibleWithJWTSubjectException;
use Iqbalatma\LaravelJwtAuthentication\Interfaces\JWTKey;
use Iqbalatma\LaravelJwtAuthentication\Interfaces\JWTSubject;
use Iqbalatma\LaravelJwtAuthentication\Services\JWTService;
use Iqbalatma\LaravelJwtAuthentication\Traits\IssuedTokenHelper;
use stdClass;

abstract class BaseJWTService
{
    use IssuedTokenHelper;

    protected string|null $userAgent;
    protected int $accessTokenTTL;
    protected int $refreshTTL;
    protected array $payload;
    protected array $requestTokenPayloads;
    protected stdClass $requestTokenHeaders;

    /**
     * @throws MissingRequiredHeaderException
     */
    public function __construct(protected JWTKey $jwtKey)
    {
        $this->accessTokenTTL = config("jwt.access_token_ttl");
        $this->refreshTTL = config("jwt.refresh_token_ttl");
        $this->userAgent = request()->userAgent();
        if (!$this->userAgent) {
            throw new MissingRequiredHeaderException("Missing required header User-Agent");
        }
    }


    /**
     * @return void
     */
    protected function setDefaultPayload(): void
    {
        $now = time();
        if (!Cache::get("jwt.latest_incident_date_time")) {
            Cache::forever("jwt.latest_incident_date_time", $now - 1);
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
