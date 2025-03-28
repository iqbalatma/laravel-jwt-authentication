<?php

namespace Iqbalatma\LaravelJwtAuthentication\Services;

use Illuminate\Support\Collection;
use Illuminate\Support\Facades\Cache;
use Iqbalatma\LaravelJwtAuthentication\Enums\JWTTokenType;
use Iqbalatma\LaravelJwtAuthentication\Exceptions\JWTInvalidActionException;

class IssuedTokenService
{
    public static string $JWT_CACHE_KEY_PREFIX = "jwt";
    protected Collection $issuedTokenCollection;

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
     * @param string|int $subjectId
     * @return $this
     */
    public function refreshIssuedTokenCollection(string|int $subjectId): self
    {
        #update issued token collection
        Cache::forever(
            self::$JWT_CACHE_KEY_PREFIX . ".$subjectId",
            $this->issuedTokenCollection
        );

        return $this;
    }

    /**
     * @return $this
     * @throws JWTInvalidActionException
     */
    public function setIssuedTokenCollection(string|int|null $subjectId = null): self
    {
        if (!$subjectId) {
            throw new JWTInvalidActionException("Subject id cannot be null");
        }

        $this->issuedTokenCollection = Cache::get(self::$JWT_CACHE_KEY_PREFIX . ".$subjectId") ?? collect();

        return $this;
    }

    /**
     * @param JWTTokenType $tokenType
     * @param string $userAgent
     * @param bool $isBlacklisted
     * @param string|int|null $subjectId
     * @return $this
     */
    public function addNewIssuedToken(JWTTokenType $tokenType, string $userAgent, bool $isBlacklisted = true, string|int|null $subjectId = null): self
    {
        $this->issuedTokenCollection->push([
            "user_agent" => $userAgent,
            "type" => $tokenType->name,
            "iat" => time(),
            "is_blacklisted" => $isBlacklisted
        ]);

        if ($subjectId) {
            $this->refreshIssuedTokenCollection($subjectId);
        }
        return $this;
    }


    /**
     * @param JWTTokenType $tokenType
     * @param string $userAgent
     * @param bool $isBlacklisted
     * @param string|int|null $subjectId
     * @return $this
     */
    public function updateIssuedToken(JWTTokenType $tokenType, string $userAgent, bool $isBlacklisted = true, string|int|null $subjectId = null): self
    {
        $this->issuedTokenCollection->transform(function ($item) use ($tokenType, $userAgent, $isBlacklisted) {
            if ($item["type"] === $tokenType->name && $item["user_agent"] === $userAgent) {
                $item["iat"] = time();
                $item["is_blacklisted"] = $isBlacklisted;
            }
            return $item;
        });

        if ($subjectId) {
            $this->refreshIssuedTokenCollection($subjectId);
        }
        return $this;
    }


    /**
     * @param JWTTokenType $tokenType
     * @param string $userAgent
     * @return bool
     */
    public function isExists(JWTTokenType $tokenType, string $userAgent): bool
    {
        if (!$this->issuedTokenCollection
            ->where("type", $tokenType->name)
            ->where("user_agent", $userAgent)
            ->first()) {
            return false;
        }

        return true;
    }


    /**
     * @param string|int $subjectId
     * @return Collection
     * @throws JWTInvalidActionException
     */
    public static function getAllToken(string|int $subjectId): Collection
    {
        $service = self::build();
        $service->setIssuedTokenCollection($subjectId);

        return $service->issuedTokenCollection->filter(function ($item) {
            return $item["is_blacklisted"] === false;
        })->values();
    }


    /**
     * @param string|int $subjectId
     * @return Collection
     * @throws JWTInvalidActionException
     */
    public static function getAllRefreshToken(string|int $subjectId): Collection
    {
        $service = self::build();
        $service->setIssuedTokenCollection($subjectId);

        return $service->issuedTokenCollection->filter(function ($item) {
            return $item["type"] === JWTTokenType::REFRESH->name && $item["is_blacklisted"] === false;
        })->values();
    }


    /**
     * @param string|int $subjectId
     * @return Collection
     * @throws JWTInvalidActionException
     */
    public static function getAllAccessToken(string|int $subjectId): Collection
    {
        $service = self::build();
        $service->setIssuedTokenCollection($subjectId);

        return $service->issuedTokenCollection->filter(function ($item) {
            return $item["type"] === JWTTokenType::ACCESS->name && $item["is_blacklisted"] === false;
        })->values();
    }


    /**
     * @param string $userAgent
     * @param string|int $subjectId
     * @return IssuedTokenService
     * @throws JWTInvalidActionException
     */
    public static function revokeRefreshTokenByUserAgent(string $userAgent, string|int $subjectId): IssuedTokenService
    {
        $service = self::build();
        $service->setIssuedTokenCollection($subjectId);

        $service->updateIssuedToken(JWTTokenType::REFRESH, $userAgent, true)
            ->refreshIssuedTokenCollection($subjectId);

        return $service;
    }

    /**
     * @param string $userAgent
     * @param string|int $subjectId
     * @return IssuedTokenService
     * @throws JWTInvalidActionException
     */
    public static function revokeAccessTokenByUserAgent(string $userAgent, string|int $subjectId): IssuedTokenService
    {
        $service = self::build();
        $service->setIssuedTokenCollection($subjectId);

        $service->updateIssuedToken(JWTTokenType::ACCESS, $userAgent)
            ->refreshIssuedTokenCollection($subjectId);

        return $service;
    }


    /**
     * @param string $userAgent
     * @param string|int $subjectId
     * @return void
     * @throws JWTInvalidActionException
     */
    public static function revokeTokenByUserAgent(string $userAgent, string|int $subjectId): void
    {
        self::revokeRefreshTokenByUserAgent($userAgent, $subjectId);
        self::revokeAccessTokenByUserAgent($userAgent, $subjectId);
    }


    /**
     * @param string|int $subjectId
     * @return IssuedTokenService
     * @throws JWTInvalidActionException
     */
    public static function revokeAllToken(string|int $subjectId): IssuedTokenService
    {
        $service = self::build();
        $service->setIssuedTokenCollection($subjectId);

        $service->issuedTokenCollection->transform(function ($item) {
            $item["iat"] = now();
            return $item;
        });

        $service->refreshIssuedTokenCollection($subjectId);

        return $service;
    }

    /**
     * @param string|int $subjectId
     * @return IssuedTokenService
     * @throws JWTInvalidActionException
     */
    public static function revokeAllTokenOnOtherUserAgent(string|int $subjectId): IssuedTokenService
    {
        $service = self::build();
        $service->setIssuedTokenCollection($subjectId);

        $service->issuedTokenCollection->transform(function ($item){
            if ($item["user_agent"] !== request()->userAgent()) {
                $item["iat"] = time();
                $item["is_blacklisted"] = true;
            }
        });

        $service->refreshIssuedTokenCollection($subjectId);

        return $service;
    }
}
