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

    public const LATEST_INCIDENT_TIME_KEY = "jwt.latest_incident_date_time";

    protected string $userAgent;
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
        if (!($userAgent = request()?->userAgent())) {
            throw new MissingRequiredHeaderException();
        }
        $this->userAgent = $userAgent;
    }


    /**
     * @return void
     */
    protected function setDefaultPayload(): void
    {
        $now = time();
        self::checkIncidentTime();

        $this->payload = [
            'iss' => url()->current(),
            'iat' => $now,
            'exp' => $now,
            'nbf' => $now,
            'jti' => Str::uuid(),
            'sub' => null,
            'iua' => $this->userAgent
        ];
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
     * first initiate last incident time
     * this use when redis data is reset, but you already invoke many token,
     * you can invalidate all issued token, and make user re-logged in
     * @return void
     */
    public static function checkIncidentTime(): void
    {
        if (!Cache::get(self::LATEST_INCIDENT_TIME_KEY)) {
            $now = time();
            Cache::forever(self::LATEST_INCIDENT_TIME_KEY, $now - 1);
        }
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
