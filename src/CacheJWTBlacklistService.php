<?php

namespace Iqbalatma\LaravelJwtAuthentication;

use Exception;
use Illuminate\Support\Facades\Cache;
use Iqbalatma\LaravelJwtAuthentication\Enums\TokenType;
use Iqbalatma\LaravelJwtAuthentication\Exceptions\MissingRequiredHeaderException;
use Iqbalatma\LaravelJwtAuthentication\Interfaces\JWTBlacklistService;

class CacheJWTBlacklistService implements JWTBlacklistService
{
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
        if (!request()->userAgent()){
            throw new MissingRequiredHeaderException("Missing required header User-Agent");
        }
        $this->userAgent = request()->userAgent();

        $this->subjectId = $this->jwtService->getRequestedTokenPayloads("sub");
        $this->iat = $this->jwtService->getRequestedTokenPayloads("iat");
        $this->tokenType = $this->jwtService->getRequestedTokenPayloads("type");
    }

    /**
     * @param int $incidentTime
     * @return bool
     */
    public function isTokenBlacklisted(int $incidentTime): bool
    {
        $cachePrefix = self::JWT_KEY_PREFIX;

        /**
         * this is condition when redis got incident, and latest incident date time is updated and reset
         * so when token is below incident date time, it's mean there is possibility that token already on blacklist
         * but since redis got incident and deleted, it will be considered as valid token
         * so, we need to check if incident time is greater or equal than iat
         */
        if ($incidentTime >= $this->iat) {
            $this->blacklistToken(true);
            return true;
        }
        /**
         * is token is blacklisted and blacklisted token iat is greater than requested iat, it's mean requested iat is invalid
         */
        if ($blacklistedIag = Cache::get("$cachePrefix.$this->tokenType.$this->subjectId.$this->userAgent")) {
            return $blacklistedIag >= $this->iat;
        }

        return false;
    }


    /**
     * @param bool $isBlacklistBothToken
     * @return void
     */
    public function blacklistToken(bool $isBlacklistBothToken = false): void
    {
        $cachePrefix = self::JWT_KEY_PREFIX;

        $accessTokenTTL = config("jwt_iqbal.access_token_ttl");
        $refreshTokenTTL = config("jwt_iqbal.refresh_token_ttl");

        if ($isBlacklistBothToken){
            Cache::put("$cachePrefix.".TokenType::REFRESH->value.".$this->subjectId.$this->userAgent", $this->iat, $refreshTokenTTL);
            Cache::put("$cachePrefix.".TokenType::ACCESS->value.".$this->subjectId.$this->userAgent", $this->iat, $accessTokenTTL);
        }else{
            if ($this->tokenType === TokenType::REFRESH->value){
                $ttl = $refreshTokenTTL;
            }else{
                $ttl = $accessTokenTTL;
            }
            Cache::put("$cachePrefix.$this->tokenType.$this->subjectId.$this->userAgent", $this->iat, $ttl);
        }
    }
}
