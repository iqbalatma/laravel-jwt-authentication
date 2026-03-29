<?php

namespace Iqbalatma\LaravelJwtAuthentication\Middleware;

use Closure;
use Exception;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Cookie;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Str;
use Iqbalatma\LaravelJwtAuthentication\Enums\JWTTokenType;
use Iqbalatma\LaravelJwtAuthentication\Exceptions\JWTAccessTokenIssuerMismatchException;
use Iqbalatma\LaravelJwtAuthentication\Exceptions\JWTInvalidActionException;
use Iqbalatma\LaravelJwtAuthentication\Exceptions\JWTInvalidTokenException;
use Iqbalatma\LaravelJwtAuthentication\Exceptions\JWTInvalidTokenTypeException;
use Iqbalatma\LaravelJwtAuthentication\Exceptions\JWTMissingRequiredTokenException;
use Iqbalatma\LaravelJwtAuthentication\Exceptions\JWTUnauthenticatedUserException;
use Iqbalatma\LaravelJwtAuthentication\Interfaces\JWTBlacklistService;
use Iqbalatma\LaravelJwtAuthentication\Services\DecodingService;
use Iqbalatma\LaravelJwtAuthentication\Services\IncidentTimeService;
use Symfony\Component\HttpFoundation\Response;

class AuthenticateMiddleware
{
    protected string|null $tokenFromRequest;
    protected bool $isRefreshTokenFromHeader;
    protected string $tokenType;
    protected string|null $accessTokenVerifierFromCookie;

    public function __construct(protected DecodingService $decodingService, protected readonly Request $request)
    {
        $this->tokenFromRequest = null;
        $this->isRefreshTokenFromHeader = false;
        $this->tokenType = "";
        $this->accessTokenVerifierFromCookie = Cookie::get(config("jwt.access_token_verifier.key"));
    }

    /**
     * @param Request $request
     * @param Closure $next
     * @param string $tokenType
     * @return Response
     * @throws JWTInvalidTokenException
     * @throws JWTInvalidTokenTypeException
     * @throws JWTMissingRequiredTokenException
     * @throws JWTUnauthenticatedUserException
     * @throws JWTAccessTokenIssuerMismatchException
     * @throws JWTInvalidActionException
     */
    public function handle(Request $request, Closure $next, string $tokenType = JWTTokenType::ACCESS->name): Response
    {
        IncidentTimeService::check();
        $this->checkMiddlewareTokenType($tokenType)
            ->setToken()
            ->checkIsTokenSignatureValid()
            ->checkTokenType()
            ->checkTokenBlacklist()
            ->checkAccessTokenVerifier()
            ->setAuthenticatedUser();

        return $next($request);
    }


    /**
     * @param string $tokenType
     * @return $this
     * @throws JWTInvalidTokenTypeException
     */
    protected function checkMiddlewareTokenType(string $tokenType): self
    {
        $this->tokenType = strtoupper($tokenType);
        if (!in_array($tokenType, JWTTokenType::names(), true)) {
            throw new JWTInvalidTokenTypeException();
        }

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
     * @param string|null $token
     * @return AuthenticateMiddleware
     * @throws JWTInvalidTokenException
     * @throws JWTMissingRequiredTokenException
     */
    protected function setToken(string|null $token = null): self
    {
        if ($token) {
            $this->tokenFromRequest = $token;
            return $this;
        }

        #FOR ACCESS TOKEN
        if ($this->tokenType === JWTTokenType::ACCESS->name) {
            if (!$this->request->hasHeader("authorization") || $this->request->header("authorization") === null) {
                throw new JWTMissingRequiredTokenException("Missing required header Authorization");
            }

            $this->tokenFromRequest = $this->request->bearerToken();
        } else {
            #FOR REFRESH TOKEN
            $jwtRefreshToken = null;
            if (Cookie::get(config("jwt.refresh_token.key"))) {
                $jwtRefreshToken = Cookie::get(config("jwt.refresh_token.key"));
            } else {
                $jwtRefreshToken = $this->request->bearerToken();
                $this->isRefreshTokenFromHeader = true;
            }

            if (!$jwtRefreshToken) {
                throw new JWTMissingRequiredTokenException("Missing required jwt refresh token");
            }

            $this->tokenFromRequest = $jwtRefreshToken;
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
     * @throws JWTMissingRequiredTokenException
     */
    protected function checkIsTokenSignatureValid(): self
    {
        $signature = explode(".", $this->tokenFromRequest)[2] ?? null;
        if ($payload = Cache::get($signature)) {
            $this->decodingService->setRequestedTokenPayloads(json_decode($payload, true));
        } else {
            $this->decodingService->decodeJWT($this->tokenFromRequest);
            if ($this->isRefreshTokenFromHeader && $this->decodingService->getIsUsingCookie()) {
                throw new JWTMissingRequiredTokenException("Missing required cookie jwt refresh token");
            }

            Cache::put($signature, json_encode($this->decodingService->getRequestedTokenPayloads()), config("jwt.access_token_ttl"));
        }

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
        $accessTokenVerifierFromJWT = $this->decodingService->getRequestedAtv();
        $hashFromCookie = Cache::get($this->accessTokenVerifierFromCookie);
        $isAtvValid = false;
        if ($hashFromCookie) {
            $isAtvValid = $hashFromCookie === $accessTokenVerifierFromJWT;
        }

        // 3. Jika tidak ada di cache, lakukan pengecekan Hash yang berat (Slow Path)
        if (!$isAtvValid &&
            hash_equals(
                $hashFromCookie = base64_encode(hash_hmac(
                    'sha256',
                    $this->accessTokenVerifierFromCookie,
                    config("app.key"), true)),
                $accessTokenVerifierFromJWT
            )) {
            $isAtvValid = true;
            Cache::put(
                $this->accessTokenVerifierFromCookie,
                $hashFromCookie,
                config("jwt.access_token_ttl")
            );
        }

        // 4. Cek apakah kondisi pemblokiran terpenuhi
        $isUsingCookie = $this->decodingService->getIsUsingCookie();
        $isAccessToken = $this->decodingService->getRequestedType() === JWTTokenType::ACCESS->name;
        $isEnabledInConfig = config("jwt.is_using_access_token_verifier");
        if ($isEnabledInConfig && $isAccessToken && $isUsingCookie && !$isAtvValid) {
            #blacklist token, could be stolen token via xss
            (new \Iqbalatma\LaravelJwtAuthentication\Services\JWTBlacklistService($this->decodingService))
                ->blacklistToken(true);

            throw new JWTAccessTokenIssuerMismatchException();
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
     * @return AuthenticateMiddleware
     * @throws JWTInvalidTokenTypeException
     */
    protected function checkTokenType(): self
    {
        $tokenType = $this->tokenType;
        /**
         * check condition when requested token type is different with middleware token type
         */
        if (($requestedTokenType = $this->decodingService->getRequestedType()) !== $tokenType) {
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
        $user = Auth::getProvider()->retrieveById($this->decodingService->getRequestedSub());
        if (!$user) {
            throw new JWTUnauthenticatedUserException("User of this token does not exists");
        }
        Auth::guard(config("jwt.guard"))->setUser($user);

        $accessToken = "";
        if ($this->tokenType === JWTTokenType::ACCESS->name) {
            $accessToken = $this->request->bearerToken() ?? "";
        }

        $refreshToken = (Cookie::get(config("jwt.refresh_token.key")) ?? $this->request->bearerToken()) ?? "";
        $accessTokenVerifier = $this->accessTokenVerifierFromCookie ?? "";


        Auth::guard(config("jwt.guard"))->setAccessToken($accessToken);
        Auth::guard(config("jwt.guard"))->setRefreshToken($refreshToken);
        Auth::guard(config("jwt.guard"))->setAccessTokenVerifier($accessTokenVerifier);
    }
}
