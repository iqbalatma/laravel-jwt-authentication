<?php

namespace Iqbalatma\LaravelJwtAuthentication\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Iqbalatma\LaravelJwtAuthentication\Contracts\Interfaces\JWTBlacklistService;
use Iqbalatma\LaravelJwtAuthentication\Enums\JWTTokenType;
use Iqbalatma\LaravelJwtAuthentication\Exceptions\JWTInvalidIssuedUserAgent;
use Iqbalatma\LaravelJwtAuthentication\Exceptions\JWTInvalidTokenException;
use Iqbalatma\LaravelJwtAuthentication\Exceptions\JWTInvalidTokenTypeException;
use Iqbalatma\LaravelJwtAuthentication\Exceptions\JWTMissingRequiredHeaderException;
use Iqbalatma\LaravelJwtAuthentication\Exceptions\JWTMissingRequiredTokenException;
use Iqbalatma\LaravelJwtAuthentication\Exceptions\JWTUnauthenticatedUserException;
use Iqbalatma\LaravelJwtAuthentication\Services\IncidentTimeService;
use Iqbalatma\LaravelJwtAuthentication\Services\JWTService;
use Symfony\Component\HttpFoundation\Response;

class AuthenticateMiddleware
{
    protected string|null $userAgentFromRequest;
    protected string|null $tokenFromRequest;

    public function __construct(protected JWTService $jwtService, protected readonly Request $request)
    {
        $this->userAgentFromRequest = null;
        $this->tokenFromRequest = null;
    }

    /**
     * @param Request $request
     * @param Closure $next
     * @param string $tokenType
     * @return Response
     * @throws JWTInvalidIssuedUserAgent
     * @throws JWTInvalidTokenException
     * @throws JWTInvalidTokenTypeException
     * @throws JWTMissingRequiredHeaderException
     * @throws JWTMissingRequiredTokenException
     * @throws JWTUnauthenticatedUserException
     */
    public function handle(Request $request, Closure $next, string $tokenType = JWTTokenType::ACCESS->name): Response
    {
        IncidentTimeService::check();
        $this->setUserAgent()
            ->setToken()
            ->checkIsTokenSignatureValid()
            ->checkUserAgent()
            ->checkTokenType($tokenType)
            ->checkTokenBlacklist()
            ->setAuthenticatedUser();

        return $next($request);
    }

    /**
     * @param string|null $userAgent
     * @return AuthenticateMiddleware
     * @throws JWTMissingRequiredHeaderException
     */
    protected function setUserAgent(string|null $userAgent = null): self
    {
        if ($userAgent) {
            $this->userAgentFromRequest = $userAgent;
            return $this;
        }

        if (!$this->request->userAgent()) {
            throw new JWTMissingRequiredHeaderException("Missing required header User-Agent");
        }

        $this->userAgentFromRequest = $this->request->userAgent();

        return $this;
    }


    /**
     * @param string|null $token
     * @return AuthenticateMiddleware
     * @throws JWTMissingRequiredTokenException
     */
    protected function setToken(string|null $token = null): self
    {
        if ($token) {
            $this->tokenFromRequest = $token;
            return $this;
        }

        if (!$this->request->hasHeader("authorization")) {
            throw new JWTMissingRequiredTokenException("Missing required header Authorization");
        }

        $this->tokenFromRequest = $this->request->bearerToken();

        return $this;
    }


    /**
     * @description check token signature and payload
     * against secret key or openssl
     * @return AuthenticateMiddleware
     */
    protected function checkIsTokenSignatureValid(): self
    {
        $this->jwtService->decodeJWT($this->tokenFromRequest);
        return $this;
    }

    /**
     * @description when token generate from user agent A
     * but, when check token and user send it from user agent B
     * we will throw JWTInvalidIssuedUserAgent and blacklist that token
     * @return AuthenticateMiddleware
     * @throws JWTInvalidIssuedUserAgent
     */
    protected function checkUserAgent(): self
    {
        if (($iua = $this->jwtService->getRequestedIua()) !== $this->userAgentFromRequest) {
            resolve(JWTBlacklistService::class)->blacklistToken(userAgent: $iua);
            throw new JWTInvalidIssuedUserAgent();
        }
        return $this;
    }


    /**
     * @description when user pass token type refresh to endpoint that require token type
     * access, request will be rejected.
     * Every token has their own type, and this type will check
     * against middleware type that
     * example: auth.jwt:REFRESH
     * default type is ACCESS
     *
     * @param string $tokenType
     * @return AuthenticateMiddleware
     * @throws JWTInvalidTokenTypeException
     */
    protected function checkTokenType(string $tokenType): self
    {
        $tokenType = strtoupper($tokenType);
        if (!in_array($tokenType, JWTTokenType::names(), true)) {
            throw new JWTInvalidTokenTypeException();
        }

        /**
         * check condition when requested token type is different with middleware token type
         */
        if (($requestedTokenType = $this->jwtService->getRequestedType()) !== $tokenType) {
            throw new JWTInvalidTokenTypeException("This protected resource need token type $tokenType, and you provide $requestedTokenType");
        }

        return $this;
    }


    /**
     * @return self
     * @throws JWTInvalidTokenException
     */
    protected function checkTokenBlacklist(): self
    {
        if (resolve(JWTBlacklistService::class)->isTokenBlacklisted()) {
            throw new JWTInvalidTokenException();
        }

        return $this;
    }


    /**
     * @return void
     * @throws JWTUnauthenticatedUserException
     */
    protected function setAuthenticatedUser(): void
    {
        $user = Auth::getProvider()->retrieveById($this->jwtService->getRequestedSub());
        if (!$user) {
            throw new JWTUnauthenticatedUserException("User of this token does not exists");
        }
        Auth::setUser($user);
    }
}
