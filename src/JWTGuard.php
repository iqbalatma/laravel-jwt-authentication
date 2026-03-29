<?php

namespace Iqbalatma\LaravelJwtAuthentication;

use Illuminate\Auth\Events\Login;
use Illuminate\Auth\GuardHelpers;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\Authenticatable as AuthenticatableContract;
use Illuminate\Contracts\Auth\Guard;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Str;
use Iqbalatma\LaravelJwtAuthentication\Enums\JWTTokenType;
use Iqbalatma\LaravelJwtAuthentication\Exceptions\JWTEntityDoesNotExistsException;
use Iqbalatma\LaravelJwtAuthentication\Exceptions\JWTInvalidActionException;
use Iqbalatma\LaravelJwtAuthentication\Exceptions\JWTInvalidTokenTypeException;
use Iqbalatma\LaravelJwtAuthentication\Exceptions\JWTMissingRequiredHeaderException;
use Iqbalatma\LaravelJwtAuthentication\Exceptions\JWTModelNotCompatibleWithJWTSubjectException;
use Iqbalatma\LaravelJwtAuthentication\Exceptions\JWTUnauthenticatedUserException;
use Iqbalatma\LaravelJwtAuthentication\Interfaces\JWTBlacklistService;
use Iqbalatma\LaravelJwtAuthentication\Interfaces\JWTSubject;
use Iqbalatma\LaravelJwtAuthentication\Services\DecodingService;
use Iqbalatma\LaravelJwtAuthentication\Services\EncodingService;
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
    protected string|null $accessTokenVerifier;

    public function __construct(
        protected EncodingService $encodingService,
        protected DecodingService $decodingService,
        UserProvider              $provider,
        protected Dispatcher      $events
    )
    {
        $this->provider = $provider;
        $this->user = null;
        $this->accessToken = null;
        $this->refreshToken = null;
        $this->accessTokenVerifier = null;
    }


    /**
     * @return Authenticatable|null
     */
    public function user(): Authenticatable|null
    {
        if (!$this->user) {
            if ($this->decodingService->getRequestedSub()){
                $this->setUser(Auth::getProvider()->retrieveById($this->decodingService->getRequestedSub()));
            }
        }

        return $this->user;
    }

    /**
     * Set the current user.
     *
     * @param AuthenticatableContract|JWTSubject|null $user
     * @return $this
     */
    public function setUser(AuthenticatableContract|JWTSubject|null $user): self
    {
        $this->user = $user;

        return $this;
    }

    /**
     * Fire the login event.
     *
     * @param AuthenticatableContract|JWTSubject $user
     * @param bool $remember
     *
     * @return void
     */
    protected function fireLoginEvent(Authenticatable|JWTSubject $user, bool $remember = false): void
    {
        $this->events->dispatch(new Login(
            $this->name,
            $user,
            $remember
        ));
    }

    /**
     * @param array $credentials
     * @param bool $isUsingCookie
     * @return bool
     * @throws JWTInvalidActionException
     * @throws JWTMissingRequiredHeaderException
     * @throws JWTModelNotCompatibleWithJWTSubjectException
     */
    public function validate(array $credentials = [], bool $isUsingCookie = true): bool
    {
        return (bool)$this->attempt(credentials: $credentials, isUsingCookie: $isUsingCookie, isGetToken: false);
    }


    /**
     * @param array $credentials
     * @param bool $isUsingCookie
     * @param bool $isGetToken
     * @return bool|array
     * @throws JWTModelNotCompatibleWithJWTSubjectException
     * @throws JWTMissingRequiredHeaderException
     */
    public function attempt(array $credentials, bool $isUsingCookie = true, bool $isGetToken = true): bool|array
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
                return $this->generateAndGetToken($user, $isUsingCookie);
            }

            return true;
        }

        $this->fireFailedEvent($user, $credentials);

        return false;
    }


    /**
     * @description login is mostly used for get token from user that query not by credential
     * @param JWTSubject|null $user
     * @param bool $isUsingCookie
     * @return array
     * @throws JWTEntityDoesNotExistsException
     * @throws JWTMissingRequiredHeaderException
     */
    public function login(JWTSubject|null $user, bool $isUsingCookie = true): array
    {
        if (!$user) {
            throw new JWTEntityDoesNotExistsException("User does not exists !");
        }
        $this->fireLoginEvent($user);
        $this->setUser($user);

        return $this->generateAndGetToken($user, $isUsingCookie);
    }


    /**
     * #logout will invalidate current user token
     * @param bool $isBlacklistBoth
     * @return void
     */
    public function logout(bool $isBlacklistBoth = false): void
    {
        resolve(JWTBlacklistService::class)->blacklistToken($isBlacklistBoth);
        $this->user = null;
    }


    /**
     * @param JWTSubject|null $user
     * @param bool $isUsingCookie
     * @param bool $isBlacklistBoth
     * @return array
     * @throws JWTEntityDoesNotExistsException
     * @throws JWTInvalidActionException
     * @throws JWTInvalidTokenTypeException
     * @throws JWTMissingRequiredHeaderException
     * @throws JWTUnauthenticatedUserException
     */
    public function refreshToken(JWTSubject|null $user, bool $isUsingCookie = true, bool $isBlacklistBoth = true): array
    {
        if ($this->decodingService->getRequestedType() !== JWTTokenType::REFRESH->name) {
            throw new JWTInvalidTokenTypeException("Refresh token only can be done using refresh token type authorization");
        }

        if (!$user) {
            throw new JWTUnauthenticatedUserException("Regenerate token failed. User is not defined");
        }

        resolve(JWTBlacklistService::class)->blacklistToken($isBlacklistBoth);

        #this login already generate access token and refresh token so we can call access token and refresh token directly
        $this->login($user, $isUsingCookie);

        return [
            "access_token" => $this->accessToken,
            "refresh_token" => $this->refreshToken,
            "access_token_verifier" => $this->accessTokenVerifier
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

    /**
     * @return string|null
     */
    public function getRefreshToken(): string|null
    {
        return $this->refreshToken;
    }

    /**
     * @return string|null
     */
    public function getAccessToken(): string|null
    {
        return $this->accessToken;
    }

    /**
     * @return string|null
     */
    public function getAccessTokenVerifier(): string|null
    {
        return $this->accessTokenVerifier;
    }

    /**
     * @param string $accessToken
     * @return void
     */
    public function setAccessToken(string $accessToken): void
    {
        $this->accessToken = $accessToken;
    }

    /**
     * @param string $refreshToken
     * @return void
     */
    public function setRefreshToken(string $refreshToken): void
    {
        $this->refreshToken = $refreshToken;
    }

    /**
     * @param string $accessTokenVerifier
     * @return void
     */
    public function setAccessTokenVerifier(string $accessTokenVerifier): void
    {
        $this->accessTokenVerifier = $accessTokenVerifier;
    }


    /**
     * @param JWTSubject $user
     * @param bool $isUsingCookie
     * @return array
     * @throws JWTMissingRequiredHeaderException
     */
    public function generateAndGetToken(JWTSubject $user, bool $isUsingCookie): array
    {
        $this->accessTokenVerifier = Str::random(32);
        $accessTokenJti = Str::uuid();
        $refreshTokenJti = Str::uuid();
        $this->accessToken = $this->encodingService->generateToken(
            type: JWTTokenType::ACCESS,
            user: $user,
            atv: $this->accessTokenVerifier,
            isUsingCookie: $isUsingCookie,
            jti: $accessTokenJti,
            pti: $refreshTokenJti
        );
        $this->refreshToken = $this->encodingService->generateToken(
            type: JWTTokenType::REFRESH,
            user: $user,
            isUsingCookie: $isUsingCookie,
            jti: $refreshTokenJti,
            pti: $accessTokenJti
        );
        return [
            "access_token" => $this->accessToken,
            "refresh_token" => $this->refreshToken,
            "access_token_verifier" => $this->accessTokenVerifier
        ];
    }
}
