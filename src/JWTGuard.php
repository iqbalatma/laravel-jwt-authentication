<?php

namespace Iqbalatma\LaravelJwtAuthentication;

use Illuminate\Contracts\Auth\Authenticatable;
use Iqbalatma\LaravelJwtAuthentication\Abstracts\BaseJWTGuard;
use Iqbalatma\LaravelJwtAuthentication\Exceptions\EntityDoesNotExistsException;
use Iqbalatma\LaravelJwtAuthentication\Exceptions\InvalidActionException;
use Iqbalatma\LaravelJwtAuthentication\Exceptions\ModelNotCompatibleWithJWTSubjectException;
use Iqbalatma\LaravelJwtAuthentication\Interfaces\JWTSubject;

/**
 * @method static attempt()
 */
class JWTGuard extends BaseJWTGuard
{
    /**
     * @return Authenticatable|null
     */
    public function user(): Authenticatable|null
    {
        if ($this->user !== null) {
            return $this->user;
        }

        return null;
    }

    /**
     * @throws ModelNotCompatibleWithJWTSubjectException|Exceptions\InvalidActionException
     */
    public function validate(array $credentials = []): bool
    {
        return (bool) $this->attempt($credentials, false);
    }


    /**
     * Use to attempt login user using credentials
     * @param array $credentials
     * @param bool $isGetToken
     * @return bool|string
     * @throws ModelNotCompatibleWithJWTSubjectException|Exceptions\InvalidActionException
     */
    public function attempt(array $credentials, bool $isGetToken = true): bool|array
    {
        $this->lastAttempted = $user = $this->provider->retrieveByCredentials($credentials);

        $this->fireAttemptEvent($credentials);

        $validated = $user !== null && $this->provider->validateCredentials($user, $credentials);
        if ($validated) {
            $this->setUser($user);
            $this->fireValidatedEvent($user);

            if ($isGetToken) {
                $this->accessToken = $this->jwtService->generateAccessToken($this->user());
                $this->refreshToken = $this->jwtService->generateRefreshToken($this->user());

                return [
                    "access_token" => $this->getAccessToken(),
                    "refresh_token" => $this->getRefreshToken(),
                ];
            }

            return true;
        }

        $this->fireFailedEvent($user, $credentials);

        return false;
    }

    /**
     * @param JWTSubject|null $user
     * @return void
     * @throws ModelNotCompatibleWithJWTSubjectException|EntityDoesNotExistsException|Exceptions\InvalidActionException
     */
    public function login(JWTSubject|null $user):void
    {
        if (!$user){
            throw new EntityDoesNotExistsException("User does not exists !");
        }
        $this->fireLoginEvent($user);
        $this->accessToken = $this->jwtService->generateAccessToken($user);
        $this->refreshToken = $this->jwtService->generateRefreshToken($user);
    }

    /**
     * @return void
     * @throws InvalidActionException
     */
    public function logout(): void
    {
        $this->setSubjectCacheRecord($this->jwtService->getRequestedSub())
            ->executeBlacklistToken($this->jwtService->getRequestedType(), request()->userAgent());
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
    public function getAccessToken(): string|null
    {
        return $this->accessToken;
    }


    /**
     * @return string|null
     */
    public function getRefreshToken(): string|null
    {
        return $this->refreshToken;
    }
}
