<?php

namespace Iqbalatma\LaravelJwtAuthentication;

use Illuminate\Support\Collection;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Cache;
use Iqbalatma\LaravelJwtAuthentication\Enums\TokenType;
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
}
