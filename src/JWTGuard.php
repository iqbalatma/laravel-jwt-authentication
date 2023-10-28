<?php

namespace Iqbalatma\LaravelJwtAuthentication;

use Illuminate\Contracts\Auth\Authenticatable;
use Iqbalatma\LaravelJwtAuthentication\Abstracts\BaseJWTGuard;
use Iqbalatma\LaravelJwtAuthentication\Exceptions\ModelNotCompatibleWithJWTSubjectException;

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

    public function validate(array $credentials = [])
    {
        $user = $this->provider->retrieveByCredentials($credentials);

        return $this->hasValidCredentials($user, $credentials);
    }


    /**
     * Use to attempt login user using credentials
     * @param array $credentials
     * @param bool $isGetToken
     * @return bool|string
     * @throws ModelNotCompatibleWithJWTSubjectException
     */
    public function attempt(array $credentials, bool $isGetToken = true): bool|array
    {
        /**
         * todo : fire attempt event
         */
        if ($this->validate($credentials)) {
            $this->accessToken = $this->jwtService->generateAccessToken($this->user());
            $this->refreshToken = $this->jwtService->generateRefreshToken($this->user());

            if ($isGetToken) {
                return [
                    "access_token" => $this->getAccessToken(),
                    "refresh_token" => $this->getRefreshToken(),
                ];
            }

            return true;
        }

        /**
         * todo: fire attempt failed event
         */
        return false;
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
