<?php

namespace Iqbalatma\LaravelJwtAuthentication\Middleware;

use Closure;
use Exception;
use Firebase\JWT\JWT;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Cookie;
use Iqbalatma\LaravelJwtAuthentication\Contracts\Interfaces\JWTBlacklistService;
use Iqbalatma\LaravelJwtAuthentication\Enums\JWTTokenType;
use Iqbalatma\LaravelJwtAuthentication\Exceptions\JWTAccessTokenIssuerMismatchException;
use Iqbalatma\LaravelJwtAuthentication\Exceptions\JWTInvalidActionException;
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
     * @throws JWTAccessTokenIssuerMismatchException
     * @throws JWTInvalidActionException
     */
    public function handle(Request $request, Closure $next, string $tokenType = JWTTokenType::ACCESS->name): Response
    {
        $tokenType = strtoupper($tokenType);
        if (!in_array($tokenType, JWTTokenType::names(), true)) {
            throw new JWTInvalidTokenTypeException();
        }
        IncidentTimeService::check();
        $this->setUserAgent()
            ->setToken($tokenType)
            ->checkIsTokenSignatureValid()
            ->checkUserAgent()
            ->checkTokenType($tokenType)
            ->checkTokenBlacklist()
            ->checkAccessTokenVerifier()
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
     * @param $token
     * @return bool
     */
    private function isJWT($token): bool
    {
        $parts = explode('.', $token);
        if (count($parts) !== 3) {
            return false;
        }

        list($header, $payload, $signature) = $parts;

        $isBase64Url = function ($str) {
            return preg_match('/^[A-Za-z0-9\-_]+$/', $str);
        };

        return $isBase64Url($header) && $isBase64Url($payload) && $isBase64Url($signature);
    }

    /**
     * @param string $tokenType
     * @param string|null $token
     * @return AuthenticateMiddleware
     * @throws JWTMissingRequiredTokenException
     * @throws JWTInvalidTokenException
     */
    protected function setToken(string $tokenType, string|null $token = null): self
    {
        if ($token) {
            $this->tokenFromRequest = $token;
            return $this;
        }

        if ($tokenType === JWTTokenType::ACCESS->name) {
            if (!$this->request->hasHeader("authorization") || $this->request->header("authorization") === null) {
                throw new JWTMissingRequiredTokenException("Missing required header Authorization");
            }

            $this->tokenFromRequest = $this->request->bearerToken();
        } else {
            if (getJWTRefreshTokenMechanism() === 'cookie') {
                if (!($jwtRefreshToken = Cookie::get(config("jwt.refresh_token.key")))) {
                    throw new JWTMissingRequiredTokenException("Missing required cookie jwt refresh token");
                }

                $this->tokenFromRequest = $jwtRefreshToken;
            } else {
                if (!$this->request->hasHeader("authorization")) {
                    throw new JWTMissingRequiredTokenException("Missing required header Authorization");
                }

                $this->tokenFromRequest = $this->request->bearerToken();
            }
        }

        if (!$this->isJWT($this->tokenFromRequest)) {
            throw new JWTInvalidTokenException("Invalid token format");
        }
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
     * @return $this
     * @throws JWTAccessTokenIssuerMismatchException
     * @throws JWTInvalidActionException
     * @throws Exception
     */
    protected function checkAccessTokenVerifier(): self
    {
        if (config("jwt.is_using_access_token_verifier") && $this->jwtService->getRequestedAtv() !== Cookie::get("access_token_verifier")) {
            (new \Iqbalatma\LaravelJwtAuthentication\Services\JWTBlacklistService($this->jwtService))->blacklistToken(true);
            throw new JWTAccessTokenIssuerMismatchException();
        }

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
        Auth::guard(config("jwt.guard"))->setUser($user);
    }
}
