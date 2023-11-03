<?php

namespace Iqbalatma\LaravelJwtAuthentication;

use Illuminate\Support\Collection;
use Iqbalatma\LaravelJwtAuthentication\Enums\TokenType;
use Iqbalatma\LaravelJwtAuthentication\Exceptions\InvalidActionException;

class IssuedTokenService
{

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
        $instance->jwtService->setIssuedToken($subjectId);

        return $instance->jwtService->issuedTokens->filter(function ($item) {
                return $item["is_blacklisted"] === false;
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
        $instance->jwtService->setIssuedToken($subjectId);

        return $instance->jwtService->issuedTokens->filter(function ($item) {
            return $item["type"] === TokenType::REFRESH->value && $item["is_blacklisted"] === false;
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
        $instance->jwtService->setIssuedToken($subjectId);

        return $instance->jwtService->issuedTokens->filter(function ($item) {
            return $item["type"] === TokenType::ACCESS->value && $item["is_blacklisted"] === false;
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
        $instance->jwtService->setIssuedToken($subjectId);

        $instance->jwtService->updateIssuedToken(TokenType::REFRESH->value, $userAgent)
            ->replaceIssuedTokenRecord();

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
        $instance->jwtService->setIssuedToken($subjectId);

        $instance->jwtService->updateIssuedToken(TokenType::ACCESS->value, $userAgent)
            ->replaceIssuedTokenRecord();

        return $instance;
    }


    /**
     * @param string $userAgent
     * @param string|int|null $subjectId
     * @return void
     * @throws InvalidActionException
     */
    public static function revokeTokenByUserAgent(string $userAgent, string|int|null $subjectId = null): void
    {
        self::revokeTokenAccessByUserAgent($userAgent);
        self::revokeTokenRefreshByUserAgent($userAgent);
    }


    /**
     * @param string|int|null $subjectId
     * @return IssuedTokenService
     * @throws InvalidActionException
     */
    public static function revokeAllToken(string|int|null $subjectId = null): IssuedTokenService
    {
        $instance = self::build();
        $instance->jwtService->setIssuedToken($subjectId);

        $instance->jwtService->issuedTokens = $instance->jwtService->issuedTokens->map(function ($item) {
            $item["iat"] = now();
            return $item;
        });

        $instance->jwtService->replaceIssuedTokenRecord();

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
        $instance->jwtService->setIssuedToken($subjectId);

        $instance->jwtService->issuedTokens= $instance->jwtService->issuedTokens->map(function ($item) {
            if ($item["user_agent"] !== request()->userAgent()) {
                $item["iat"] = time();
                $item["is_blacklisted"] = true;
            }
            return $item;
        });

        $instance->jwtService->replaceIssuedTokenRecord();

        return $instance;
    }
}
