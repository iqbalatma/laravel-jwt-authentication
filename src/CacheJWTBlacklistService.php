<?php

namespace Iqbalatma\LaravelJwtAuthentication;

use Exception;
use Illuminate\Support\Facades\Cache;
use Iqbalatma\LaravelJwtAuthentication\Interfaces\JWTBlacklistService;

class CacheJWTBlacklistService implements JWTBlacklistService
{
    public string $jti;
    public string $iat;
    public string $tokenType;
    public string|int $subjectId;
    public string $userAgent;
    public const JWT_KEY_PREFIX = "jwt";

    /**
     * @throws Exception
     */
    public function __construct(public JWTService $jwtService)
    {
        $this->jti = $this->jwtService->getRequestedTokenPayloads("jti");
        $this->subjectId = $this->jwtService->getRequestedTokenPayloads("sub");
        $this->iat = $this->jwtService->getRequestedTokenPayloads("iat");
        $this->tokenType = $this->jwtService->getRequestedTokenPayloads("type");
        $this->userAgent = request()->header("user-agent");
    }

    /**
     * @return bool
     */
    public function isTokenBlacklisted(): bool
    {
        $cachePrefix = self::JWT_KEY_PREFIX;

        /**
         * is token is blacklisted and blacklisted token iat is greater than requested iat, it's mean requested iat is invalid
         */
        if ($blacklistedIag = Cache::get("$cachePrefix.$this->tokenType.$this->subjectId.$this->userAgent")){
            return $blacklistedIag >= $this->iat;
        }

        return false;
    }

    public function blacklistToken():void
    {
        $cachePrefix = self::JWT_KEY_PREFIX;
        Cache::set("$cachePrefix.$this->tokenType.$this->subjectId.$this->userAgent", $this->iat);
    }
}
