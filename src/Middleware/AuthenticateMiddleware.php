<?php

namespace Iqbalatma\LaravelJwtAuthentication\Middleware;

use Closure;
use Exception;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Cache;
use Iqbalatma\LaravelJwtAuthentication\Abstracts\BaseJWTService;
use Iqbalatma\LaravelJwtAuthentication\Enums\TokenType;
use Iqbalatma\LaravelJwtAuthentication\Exceptions\InvalidIssuedUserAgent;
use Iqbalatma\LaravelJwtAuthentication\Exceptions\InvalidTokenException;
use Iqbalatma\LaravelJwtAuthentication\Exceptions\InvalidTokenTypeException;
use Iqbalatma\LaravelJwtAuthentication\Exceptions\MissingRequiredHeaderException;
use Iqbalatma\LaravelJwtAuthentication\Exceptions\MissingRequiredTokenException;
use Iqbalatma\LaravelJwtAuthentication\Interfaces\JWTBlacklistService;
use Iqbalatma\LaravelJwtAuthentication\Services\JWTService;
use Symfony\Component\HttpFoundation\Response;

class AuthenticateMiddleware
{
    protected string $token;
    protected string|null $userAgent;
    protected int|null $incidentTime;

    public function __construct(protected JWTService $jwtService, protected readonly Request $request)
    {
    }

    /**
     * @param Request $request
     * @param Closure $next
     * @param string $tokenType
     * @return Response
     * @throws InvalidIssuedUserAgent
     * @throws InvalidTokenException
     * @throws InvalidTokenTypeException
     * @throws MissingRequiredHeaderException
     * @throws MissingRequiredTokenException
     */
    public function handle(Request $request, Closure $next, string $tokenType = TokenType::ACCESS->value): Response
    {
        $this->setUserAgent()
            ->checkIncidentTime()
            ->setToken()
            ->checkIsTokenSignatureValid()
            ->checkUserAgent()
            ->checkTokenType($tokenType)
            ->checkTokenBlacklist()
            ->setAuthenticatedUser();
        return $next($request);
    }


    /**
     * @return $this
     * @throws MissingRequiredHeaderException
     */
    protected function setUserAgent():self
    {
        #check user agent
        $this->userAgent = $this->request->userAgent();
        if (!$this->userAgent) {
            throw new MissingRequiredHeaderException("Missing required header User-Agent");
        }
        return $this;
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
     * @description check token signature and payload
     * against secret key or openssl
     * @return AuthenticateMiddleware
     * @throws InvalidTokenException
     */
    protected function checkIsTokenSignatureValid(): self
    {
        try {
            $this->jwtService->decodeJWT($this->token);
        } catch (Exception $e) {
            throw new InvalidTokenException();
        }

        return $this;
    }

    /**
     * @return AuthenticateMiddleware
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
     * @description when user pass token type refresh to endpoint that require token type
     * access, request will be rejected.
     * Every token has their own type, and this type will check
     * against middleware type that
     * example: auth.jwt:refresh
     * default type is access
     *
     * @param string $tokenType
     * @return AuthenticateMiddleware
     * @throws InvalidTokenTypeException
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
            throw new InvalidTokenTypeException("This protected resource need token type $tokenType, and you provide $requestedTokenType");
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
}
