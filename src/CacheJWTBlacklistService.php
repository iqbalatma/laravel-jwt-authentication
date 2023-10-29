<?php

namespace Iqbalatma\LaravelJwtAuthentication;

use Exception;
use Illuminate\Support\Collection;
use Illuminate\Support\Facades\Cache;
use Iqbalatma\LaravelJwtAuthentication\Enums\TokenType;
use Iqbalatma\LaravelJwtAuthentication\Exceptions\MissingRequiredHeaderException;
use Iqbalatma\LaravelJwtAuthentication\Interfaces\JWTBlacklistService;
use Iqbalatma\LaravelJwtAuthentication\Traits\BlacklistTokenHelper;

class CacheJWTBlacklistService implements JWTBlacklistService
{
    use BlacklistTokenHelper;

    public string $jti;
    public string $iat;
    public string $exp;
    public string $tokenType;
    public string|int $requestSubjectId;
    public string $userAgent;

    /**
     * @throws Exception
     */
    public function __construct(public JWTService $jwtService)
    {
        if (!request()->userAgent()) {
            throw new MissingRequiredHeaderException("Missing required header User-Agent");
        }
        $this->userAgent = request()->userAgent();

        $this->jti = $this->jwtService->getRequestedTokenPayloads("jti");
        $this->exp = $this->jwtService->getRequestedTokenPayloads("exp");
        $this->requestSubjectId = $this->jwtService->getRequestedTokenPayloads("sub");
        $this->iat = $this->jwtService->getRequestedTokenPayloads("iat");
        $this->tokenType = $this->jwtService->getRequestedTokenPayloads("type");
    }

    /**
     * @param int $incidentTime
     * @return bool
     */
    public function isTokenBlacklisted(int $incidentTime): bool
    {
        $cachePrefix = self::$jwtKeyPrefix;


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
         * this is the condition when cache record for this subject is not set,
         * so the token must be not blacklisted yet
         * @var $issuedTokenBySubject Collection
         */
        if (!($issuedTokenBySubject = Cache::get("$cachePrefix.$this->requestSubjectId"))) {
            Cache::forever("$cachePrefix.$this->requestSubjectId", collect([]));
            return false;
        }

        /**
         * when user agent, type, and iat greater than current iat exists,
         * it's mean current iat is no longer valid
         * because the valid token is when iat greater than blacklisted iat
         */
        if ($issuedTokenBySubject->where("user_agent", $this->userAgent)
            ->where('type', $this->tokenType)
            ->where('iat', ">=", $this->iat)
            ->first()) {
            return true;
        }

        return false;
    }


    /**
     * @param bool $isBlacklistBothToken
     * @param string|null $userAgent
     * @return void
     */
    public function blacklistToken(bool $isBlacklistBothToken = false, string|null $userAgent = null): void
    {
        $this->setSubjectCacheRecord($this->requestSubjectId);

        if ($isBlacklistBothToken) {
            $this->executeBlacklistToken(TokenType::REFRESH->value, $userAgent ?? $this->userAgent);
            $this->executeBlacklistToken(TokenType::ACCESS->value, $userAgent ?? $this->userAgent);
        } else {
            $this->executeBlacklistToken($this->tokenType, $userAgent ?? $this->userAgent);
        }
    }
}
