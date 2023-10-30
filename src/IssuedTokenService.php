<?php

namespace Iqbalatma\LaravelJwtAuthentication;

use Illuminate\Support\Collection;
use Iqbalatma\LaravelJwtAuthentication\Enums\TokenType;
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
            return $item["iat"] <= $instance->jwtService->getRequestedIat();
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
            return $item["type"] === TokenType::REFRESH->value && $item["iat"] <= $instance->jwtService->getRequestedIat();
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
            return $item["type"] === TokenType::ACCESS->value && $item["iat"] <= $instance->jwtService->getRequestedIat();
        })->values();
    }


    /**
     * @param string $userAgent
     * @param string|int|null $subjectId
     * @return IssuedTokenService
     * @throws InvalidActionException
     */
    public static function revokeTokenRefreshByUserAgent(string $userAgent, string|int|null $subjectId = null): IssuedTokenService
    {
        $instance = self::build();
        $instance->setSubjectCacheRecord($subjectId);

        $instance->updateExistingBlacklistTokenByTypeAndUserAgent(TokenType::REFRESH->value, $userAgent)
            ->updateSubjectCacheRecord();

        return $instance;
    }

    /**
     * @param string $userAgent
     * @param string|int|null $subjectId
     * @return IssuedTokenService
     * @throws InvalidActionException
     */
    public static function revokeTokenAccessByUserAgent(string $userAgent, string|int|null $subjectId = null): IssuedTokenService
    {
        $instance = self::build();
        $instance->setSubjectCacheRecord($subjectId);

        $instance->updateExistingBlacklistTokenByTypeAndUserAgent(TokenType::ACCESS->value, $userAgent)
            ->updateSubjectCacheRecord();

        return $instance;
    }


    /**
     * @param string $userAgent
     * @param string|int|null $subjectId
     * @return IssuedTokenService
     * @throws InvalidActionException
     */
    public static function revokeTokenByUserAgent(string $userAgent, string|int|null $subjectId = null): IssuedTokenService
    {
        $instance = self::build();
        $instance->setSubjectCacheRecord($subjectId);

        self::revokeTokenAccessByUserAgent($userAgent, $instance->subjectId);
        self::revokeTokenRefreshByUserAgent($userAgent, $instance->subjectId);

        return $instance;
    }


    /**
     * @param string|int|null $subjectId
     * @return IssuedTokenService
     * @throws InvalidActionException
     */
    public static function revokeAllToken(string|int|null $subjectId = null): IssuedTokenService
    {
        $instance = self::build();
        $instance->setSubjectCacheRecord($subjectId);

        $instance->issuedTokenBySubject = $instance->issuedTokenBySubject->map(function ($item) {
            $item["iat"] = now();
            return $item;
        });

        $instance->updateSubjectCacheRecord();

        return $instance;
    }

    /**
     * @param string|int|null $subjectId
     * @return IssuedTokenService
     * @throws InvalidActionException
     */
    public static function revokeAllTokenOnOtherUserAgent(string|int|null $subjectId = null): IssuedTokenService
    {
        $instance = self::build();
        $instance->setSubjectCacheRecord($subjectId);

        $instance->issuedTokenBySubject = $instance->issuedTokenBySubject->map(function ($item) {
            if ($item["user_agent"] !== request()->userAgent()) {
                $item["iat"] = now();
            }
            return $item;
        });

        $instance->updateSubjectCacheRecord();

        return $instance;
    }
}
