<?php

namespace Iqbalatma\LaravelJwtAuthentication\Middleware;

use Closure;
use Exception;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Iqbalatma\LaravelJwtAuthentication\Abstracts\BaseJWTService;
use Iqbalatma\LaravelJwtAuthentication\Enums\TokenType;
use Iqbalatma\LaravelJwtAuthentication\Exceptions\InvalidIssuedUserAgent;
use Iqbalatma\LaravelJwtAuthentication\Exceptions\InvalidTokenException;
use Iqbalatma\LaravelJwtAuthentication\Exceptions\InvalidTokenTypeException;
use Iqbalatma\LaravelJwtAuthentication\Exceptions\MissingRequiredHeaderException;
use Iqbalatma\LaravelJwtAuthentication\Exceptions\MissingRequiredTokenException;
use Iqbalatma\LaravelJwtAuthentication\Interfaces\JWTBlacklistService;
use Iqbalatma\LaravelJwtAuthentication\Services\JWTService;
use Iqbalatma\LaravelJwtAuthentication\Traits\InteractWithRequest;
use Symfony\Component\HttpFoundation\Response;

class AuthenticateMiddleware
{
    use InteractWithRequest;

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
        BaseJWTService::checkIncidentTime();
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
     * @description when token generate from user agent A
     * but, when check token and user send it from user agent B
     * we will throw InvalidIssuedUserAgent and blacklist that token
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
        if (!in_array(strtolower($tokenType), TokenType::values(), true)) {
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
        if (resolve(JWTBlacklistService::class)->isTokenBlacklisted()) {
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
