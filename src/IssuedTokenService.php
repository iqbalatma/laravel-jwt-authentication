<?php

namespace Iqbalatma\LaravelJwtAuthentication;

use Illuminate\Support\Collection;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Cache;
use Iqbalatma\LaravelJwtAuthentication\Enums\TokenType;
use Iqbalatma\LaravelJwtAuthentication\Exceptions\EntityDoesNotExistsException;
use Iqbalatma\LaravelJwtAuthentication\Traits\BlacklistTokenHelper;

class IssuedTokenService
{
    use BlacklistTokenHelper;

    /**
     * @param string|int|null $subjectId
     * @return Collection
     */
    public static function getAllToken(string|int|null $subjectId = null): Collection
    {
        if (!$subjectId) {
            $subjectId = Auth::id();
        }

        $tokens = Cache::get(self::$jwtKeyPrefix . ".$subjectId");

        return $tokens->filter(function ($item) {
            return $item["iat"] < app(JWTService::class)->getRequestedTokenPayloads("iat");
        })->values();
    }

    /**
     * @param string|int|null $subjectId
     * @return Collection
     */
    public static function getAllTokenRefresh(string|int|null $subjectId = null): Collection
    {
        if (!$subjectId) {
            $subjectId = Auth::id();
        }

        /** @var Collection|null $tokens */
        $tokens = Cache::get(self::$jwtKeyPrefix . ".$subjectId");

        return $tokens->filter(function ($item) {
            return $item["type"] === TokenType::REFRESH->value && $item["iat"] < app(JWTService::class)->getRequestedTokenPayloads("iat");
        })->values();
    }


    /**
     * @param string|int|null $subjectId
     * @return Collection
     */
    public static function getAllTokenAccess(string|int|null $subjectId = null): Collection
    {
        if (!$subjectId) {
            $subjectId = Auth::id();
        }

        /** @var Collection|null $tokens */
        $tokens = Cache::get(self::$jwtKeyPrefix . ".$subjectId");

        return $tokens->filter(function ($item) {
            return $item["type"] === TokenType::ACCESS->value && $item["iat"] < app(JWTService::class)->getRequestedTokenPayloads("iat");
        })->values();
    }


    /**
     * @param string $userAgent
     * @param string|int|null $subjectId
     * @return void
     * @throws EntityDoesNotExistsException
     */
    public static function revokeTokenRefreshByUserAgent(string $userAgent, string|int|null $subjectId = null): void
    {
        /**
         * todo: this line of code can move into single method
         */
        if (!$subjectId) {
            $subjectId = Auth::id();
        }

        $instance = (new static());
        $instance->setSubjectCacheRecord($subjectId);

        if (!$instance->isTokenBlacklistByTypeAndUserAgentExists(TokenType::REFRESH->value, $userAgent)){
            throw new EntityDoesNotExistsException("Token on device $userAgent does not exists");
        }

        $instance->updateExistingBlacklistTokenByTypeAndUserAgent(TokenType::REFRESH->value, $userAgent);
        $instance->updateSubjectCacheRecord($subjectId);
    }

    /**
     * @param string $userAgent
     * @param string|int|null $subjectId
     * @return void
     * @throws EntityDoesNotExistsException
     */
    public static function revokeTokenAccessByUserAgent(string $userAgent, string|int|null $subjectId = null): void
    {
        /**
         * todo: this line of code can move into single method
         */
        if (!$subjectId) {
            $subjectId = Auth::id();
        }

        $instance = (new static());
        $instance->setSubjectCacheRecord($subjectId);

        if (!$instance->isTokenBlacklistByTypeAndUserAgentExists(TokenType::ACCESS->value, $userAgent)){
            throw new EntityDoesNotExistsException("Token on device $userAgent does not exists");
        }

        $instance->updateExistingBlacklistTokenByTypeAndUserAgent(TokenType::ACCESS->value, $userAgent);
        $instance->updateSubjectCacheRecord($subjectId);
    }


    /**
     * @throws EntityDoesNotExistsException
     */
    public static function revokeTokenByUserAgent(string $userAgent, string|int|null $subjectId = null): void
    {
        if (!$subjectId) {
            $subjectId = Auth::id();
        }
        self::revokeTokenAccessByUserAgent($userAgent, $subjectId);
        self::revokeTokenRefreshByUserAgent($userAgent, $subjectId);
    }
}
