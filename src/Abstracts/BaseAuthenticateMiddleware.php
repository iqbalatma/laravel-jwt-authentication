<?php

namespace Iqbalatma\LaravelJwtAuthentication\Abstracts;

use Exception;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Cache;
use Iqbalatma\LaravelJwtAuthentication\Enums\TokenType;
use Iqbalatma\LaravelJwtAuthentication\Exceptions\InvalidIssuedUserAgent;
use Iqbalatma\LaravelJwtAuthentication\Exceptions\InvalidTokenException;
use Iqbalatma\LaravelJwtAuthentication\Exceptions\InvalidTokenTypeException;
use Iqbalatma\LaravelJwtAuthentication\Exceptions\MissingRequiredHeaderException;
use Iqbalatma\LaravelJwtAuthentication\Exceptions\MissingRequiredTokenException;
use Iqbalatma\LaravelJwtAuthentication\Interfaces\JWTBlacklistService;
use Iqbalatma\LaravelJwtAuthentication\Services\JWTService;

abstract class BaseAuthenticateMiddleware
{
    protected string $token;
    protected string|null $userAgent;
    protected int|null $incidentTime;

    public function __construct(protected JWTService $jwtService, protected readonly Request $request)
    {

    }


    /**
     * @return self
     */
    protected function checkIncidentTime(): self
    {
        if (!($this->incidentTime = Cache::get(BaseJWTService::LATEST_INCIDENT_TIME_KEY))) {
            $now = time();
            Cache::forever(BaseJWTService::LATEST_INCIDENT_TIME_KEY, $now);
            $this->incidentTime = $now;
        }
        return $this;
    }

    /**
     * @param string $tokenType
     * @return void
     * @throws InvalidIssuedUserAgent
     * @throws InvalidTokenException
     * @throws InvalidTokenTypeException
     * @throws MissingRequiredHeaderException
     * @throws MissingRequiredTokenException
     */
    protected function authenticate(string $tokenType): void
    {
        $this->userAgent = $this->request->userAgent();
        if (!$this->userAgent) {
            throw new MissingRequiredHeaderException("Missing required header User-Agent");
        }

        $this->checkIncidentTime()
            ->setToken()
            ->checkIsTokenValid()
            ->checkUserAgent()
            ->checkTokenType($tokenType)
            ->checkTokenBlacklist()
            ->setAuthenticatedUser();
    }

    /**
     * @return void
     * @throws InvalidTokenException
     */
    protected function setAuthenticatedUser(): void
    {
        $user = Auth::getProvider()->retrieveById($this->jwtService->getRequestedSub());
        if (!$user) {
            throw new InvalidTokenException("User of this token does not exists");
        }
        Auth::setUser($user);
    }

    /**
     * @param string $tokenType
     * @return BaseAuthenticateMiddleware
     * @throws InvalidTokenTypeException
     * @throws Exception
     */
    protected function checkTokenType(string $tokenType): self
    {
        if (strtolower($tokenType) !== TokenType::ACCESS->value && strtolower($tokenType) !== TokenType::REFRESH->value) {
            throw new InvalidTokenTypeException();
        }

        /**
         * check condition when requested token type is different with middleware token type
         */
        if (($requestedTokenType = $this->jwtService->getRequestedType()) !== $tokenType) {
            throw new InvalidTokenTypeException("This protected resource need token type $tokenType, but you provide $requestedTokenType");
        }

        return $this;
    }


    /**
     * @return self
     * @throws InvalidTokenException
     */
    protected function checkTokenBlacklist(): self
    {
        if (resolve(JWTBlacklistService::class)->isTokenBlacklisted($this->incidentTime)) {
            throw new InvalidTokenException();
        }

        return $this;
    }

    /**
     * @return self
     * @throws MissingRequiredTokenException
     */
    protected function setToken(): self
    {
        if (!$this->request->hasHeader("authorization")) {
            throw new MissingRequiredTokenException();
        }
        $this->token = $this->request->bearerToken();
        return $this;
    }


    /**
     * @return void
     * @throws InvalidIssuedUserAgent
     */
    protected function checkUserAgent(): self
    {
        if (($iua = $this->jwtService->getRequestedIua()) !== $this->userAgent) {
            resolve(JWTBlacklistService::class)->blacklistToken(userAgent: $iua);
            throw new InvalidIssuedUserAgent();
        }

        return $this;
    }


    /**
     * @return BaseAuthenticateMiddleware
     * @throws InvalidTokenException
     */
    protected function checkIsTokenValid(): self
    {
        try {
            $this->jwtService->decodeJWT($this->token);
        } catch (Exception $e) {
            throw new InvalidTokenException();
        }

        return $this;
    }
}
