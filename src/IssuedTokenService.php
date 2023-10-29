<?php

namespace Iqbalatma\LaravelJwtAuthentication;

use Illuminate\Support\Collection;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Cache;
use Iqbalatma\LaravelJwtAuthentication\Enums\TokenType;
use Iqbalatma\LaravelJwtAuthentication\Exceptions\EntityDoesNotExistsException;
use Iqbalatma\LaravelJwtAuthentication\Exceptions\InvalidActionException;
use Iqbalatma\LaravelJwtAuthentication\Traits\BlacklistTokenHelper;

class IssuedTokenService
{
    use BlacklistTokenHelper;

    public function __construct(public JWTService $jwtService)
    {
    }

    /**
     * @return static
     */
    public static function build(): self
    {
        return new static(app(JWTService::class));
    }

    /**
     * @param string|int|null $subjectId
     * @return Collection
     * @throws InvalidActionException
     */
    public static function getAllToken(string|int|null $subjectId = null): Collection
    {
        $instance = self::build();
        $instance->setSubjectCacheRecord($subjectId);

        return $instance->issuedTokenBySubject->filter(function ($item) use ($instance) {
            return $item["iat"] < $instance->jwtService->getRequestedIat();
        })->values();
    }


    /**
     * @param string|int|null $subjectId
     * @return Collection
     * @throws InvalidActionException
     */
    public static function getAllTokenRefresh(string|int|null $subjectId = null): Collection
    {
        $instance = self::build();
        $instance->setSubjectCacheRecord($subjectId);

        return $instance->issuedTokenBySubject->filter(function ($item) use ($instance) {
            return $item["type"] === TokenType::REFRESH->value && $item["iat"] < $instance->jwtService->getRequestedIat();
        })->values();
    }


    /**
     * @param string|int|null $subjectId
     * @return Collection
     * @throws InvalidActionException
     */
    public static function getAllTokenAccess(string|int|null $subjectId = null): Collection
    {
        $instance = self::build();
        $instance->setSubjectCacheRecord($subjectId);

        return $instance->issuedTokenBySubject->filter(function ($item) use ($instance) {
            return $item["type"] === TokenType::ACCESS->value && $item["iat"] < $instance->jwtService->getRequestedIat();
        })->values();
    }


    /**
     * @param string $userAgent
     * @param string|int|null $subjectId
     * @return void
     * @throws InvalidActionException
     */
    public static function revokeTokenRefreshByUserAgent(string $userAgent, string|int|null $subjectId = null): void
    {
        $instance = self::build();
        $instance->setSubjectCacheRecord($subjectId);

        $instance->updateExistingBlacklistTokenByTypeAndUserAgent(TokenType::REFRESH->value, $userAgent)
            ->updateSubjectCacheRecord();
    }

    /**
     * @param string $userAgent
     * @param string|int|null $subjectId
     * @return void
     * @throws InvalidActionException
     */
    public static function revokeTokenAccessByUserAgent(string $userAgent, string|int|null $subjectId = null): void
    {
        $instance = self::build();
        $instance->setSubjectCacheRecord($subjectId);

        $instance->updateExistingBlacklistTokenByTypeAndUserAgent(TokenType::ACCESS->value, $userAgent)
            ->updateSubjectCacheRecord();
    }


    /**
     * @throws EntityDoesNotExistsException|InvalidActionException
     */
    public static function revokeTokenByUserAgent(string $userAgent, string|int|null $subjectId = null): void
    {
        $instance = self::build();
        $instance->setSubjectCacheRecord($subjectId);

        self::revokeTokenAccessByUserAgent($userAgent, $instance->subjectId);
        self::revokeTokenRefreshByUserAgent($userAgent, $instance->subjectId);
    }
}
