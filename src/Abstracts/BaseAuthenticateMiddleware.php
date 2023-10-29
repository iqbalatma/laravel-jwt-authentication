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
use Iqbalatma\LaravelJwtAuthentication\Exceptions\MissingRequiredTokenException;
use Iqbalatma\LaravelJwtAuthentication\Interfaces\JWTBlacklistService;
use Iqbalatma\LaravelJwtAuthentication\JWTService;

abstract class BaseAuthenticateMiddleware
{
    protected string $token;
    protected int|null $incidentTime;

    /**
     * @throws MissingRequiredTokenException|InvalidTokenException
     * @throws InvalidIssuedUserAgent
     */
    public function __construct(protected JWTService $jwtService, protected readonly Request $request)
    {
        $this->checkIncidentTime()
            ->setToken()
            ->checkIsTokenValid()
            ->checkUserAgent();
    }

    private function checkIncidentTime(): self
    {
        if (!($this->incidentTime = Cache::get(config("jwt_iqbal.latest_incident_time_key")))) {
            $now = time();
            Cache::forever(config("jwt_iqbal.latest_incident_time_key"), $now);
            $this->incidentTime = $now;
        }
        return $this;
    }

    /**
     * @param string $tokenType
     * @return void
     * @throws InvalidTokenTypeException
     * @throws InvalidTokenException
     */
    protected function authenticate(string $tokenType): void
    {
        $this->checkTokenType($tokenType)
            ->checkTokenBlacklist()
            ->setAuthenticatedUser();
    }

    /**
     * @return void
     * @throws InvalidTokenException
     */
    private function setAuthenticatedUser(): void
    {
        $user = Auth::getProvider()->retrieveById($this->jwtService->getRequestedTokenPayloads("sub"));
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
    private function checkTokenType(string $tokenType): self
    {
        if (strtolower($tokenType) !== TokenType::ACCESS->value && strtolower($tokenType) !== TokenType::REFRESH->value) {
            throw new InvalidTokenTypeException();
        }

        /**
         * check condition when requested token type is different with middleware token type
         */
        if (($requestedTokenType = $this->jwtService->getRequestedTokenPayloads("type")) !== $tokenType) {
            throw new InvalidTokenTypeException("This protected resource need token type $tokenType, but you provide $requestedTokenType");
        }

        return $this;
    }


    /**
     * @return self
     * @throws InvalidTokenException
     */
    private function checkTokenBlacklist(): self
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
    private function setToken(): self
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
    private function checkUserAgent(): void
    {
        if ($this->jwtService->getRequestedTokenPayloads("iua") !== request()->userAgent()) {
            resolve(JWTBlacklistService::class)->blacklistToken(userAgent: $this->jwtService->getRequestedTokenPayloads("iua"));
            throw new InvalidIssuedUserAgent();
        }
    }


    /**
     * @return BaseAuthenticateMiddleware
     * @throws InvalidTokenException
     */
    private function checkIsTokenValid(): self
    {
        try {
            $this->jwtService->decodeJWT($this->token);
        } catch (Exception $e) {
            throw new InvalidTokenException();
        }

        return $this;
    }
}
