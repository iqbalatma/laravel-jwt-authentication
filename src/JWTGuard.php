<?php

namespace Iqbalatma\LaravelJwtAuthentication;

use Illuminate\Auth\GuardHelpers;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\Guard;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Support\Str;
use Iqbalatma\LaravelJwtAuthentication\Contracts\Interfaces\JWTBlacklistService;
use Iqbalatma\LaravelJwtAuthentication\Contracts\Interfaces\JWTSubject;
use Iqbalatma\LaravelJwtAuthentication\Enums\JWTTokenType;
use Iqbalatma\LaravelJwtAuthentication\Exceptions\JWTInvalidTokenTypeException;
use Iqbalatma\LaravelJwtAuthentication\Exceptions\JWTEntityDoesNotExistsException;
use Iqbalatma\LaravelJwtAuthentication\Exceptions\JWTInvalidActionException;
use Iqbalatma\LaravelJwtAuthentication\Exceptions\JWTModelNotCompatibleWithJWTSubjectException;
use Iqbalatma\LaravelJwtAuthentication\Exceptions\JWTUnauthenticatedUserException;
use Iqbalatma\LaravelJwtAuthentication\Services\IncidentTimeService;
use Iqbalatma\LaravelJwtAuthentication\Services\IssuedTokenService;
use Iqbalatma\LaravelJwtAuthentication\Services\JWTService;
use Iqbalatma\LaravelJwtAuthentication\Traits\AuthEventTrait;

/**
 * @description this class is call when you are calling via Auth facade
 * @method static attempt()
 */
class JWTGuard implements Guard
{
    use GuardHelpers, AuthEventTrait;

    protected Authenticatable|null $lastAttempted;

    #used in AuthEventTrait
    protected $name = 'iqbalatma.jwt';
    protected string|null $accessToken;
    protected string|null $refreshToken;

    public function __construct(
        protected JWTService $jwtService,
        UserProvider         $provider,
        protected Dispatcher $events
    )
    {
        $this->provider = $provider;
        $this->user = null;
        $this->accessToken = null;
        $this->refreshToken = null;
    }


    /**
     * @return Authenticatable|null
     */
    public function user(): Authenticatable|null
    {
        return $this->user;
    }


    /**
     * @param array $credentials
     * @return bool
     * @throws JWTInvalidActionException
     * @throws JWTModelNotCompatibleWithJWTSubjectException
     */
    public function validate(array $credentials = []): bool
    {
        return (bool)$this->attempt($credentials, false);
    }


    /**
     * @param array $credentials
     * @param bool $isGetToken
     * @return bool|array
     * @throws JWTInvalidActionException
     * @throws JWTModelNotCompatibleWithJWTSubjectException
     */
    public function attempt(array $credentials, bool $isGetToken = true): bool|array
    {
        #this is last user that attempted via this guard
        #this also retrieve user from db but not validated yet, just get the credential and password
        $this->lastAttempted = $user = $this->provider->retrieveByCredentials($credentials);
        $this->fireAttemptEvent($credentials);

        #this validated existing user with their password
        $validated = !is_null($user) && $this->provider->validateCredentials($user, $credentials);
        if ($validated) {
            $this->setUser($user)
                ->fireValidatedEvent($user);

            if (!($user instanceof JWTSubject)) {
                throw new JWTModelNotCompatibleWithJWTSubjectException();
            }
            if ($isGetToken) {
                $this->accessToken = $this->jwtService->generateToken(JWTTokenType::ACCESS, $user);
                $this->refreshToken = $this->jwtService->generateToken(JWTTokenType::REFRESH, $user);


                return [
                    "access_token" => $this->accessToken,
                    "refresh_token" => $this->refreshToken,
                    "access_token_verifier" => $this->jwtService->decodeJWT($this->accessToken)["atv"]
                ];
            }

            return true;
        }

        $this->fireFailedEvent($user, $credentials);

        return false;
    }


    /**
     * @description login is mostly used for get token from user that query not by credential
     * @param JWTSubject|null $user
     * @return void
     * @throws JWTEntityDoesNotExistsException
     * @throws JWTInvalidActionException
     */
    public function login(JWTSubject|null $user): void
    {
        if (!$user) {
            throw new JWTEntityDoesNotExistsException("User does not exists !");
        }
        $this->fireLoginEvent($user);
        $this->setUser($user);
        $this->accessToken = $this->jwtService->generateToken(JWTTokenType::ACCESS, $user);
        $this->refreshToken = $this->jwtService->generateToken(JWTTokenType::REFRESH, $user);
    }


    /**
     * #logout will invalidate current user token
     * @return void
     */
    public function logout(): void
    {
        resolve(JWTBlacklistService::class)->blacklistToken(userAgent: $this->jwtService->getRequestedIua());
        $this->user = null;
    }


    /**
     * @param JWTSubject|null $user
     * @return array
     * @throws JWTInvalidActionException
     * @throws JWTInvalidTokenTypeException
     * @throws JWTEntityDoesNotExistsException
     * @throws JWTUnauthenticatedUserException
     */
    public function refreshToken(JWTSubject|null $user): array
    {
        if ($this->jwtService->getRequestedType() !== JWTTokenType::REFRESH->name) {
            throw new JWTInvalidTokenTypeException("Refresh token only can be done using refresh token type authorization");
        }

        if (!$user) {
            throw new JWTUnauthenticatedUserException("Regenerate token failed. User is not defined");
        }

        #this login already generate access token and refresh token so we can call access token and refresh token directly
        $this->login($user);

        return [
            "access_token" => $this->accessToken,
            "refresh_token" => $this->refreshToken,
        ];
    }


    /**
     * Get the last user we attempted to authenticate.
     *
     * @return Authenticatable
     */
    public function getLastAttempted(): Authenticatable
    {
        return $this->lastAttempted;
    }
}
