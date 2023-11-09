<?php

namespace Iqbalatma\LaravelJwtAuthentication\Services;

use Exception;
use Illuminate\Support\Collection;
use Illuminate\Support\Facades\Cache;
use Iqbalatma\LaravelJwtAuthentication\Enums\TokenType;
use Iqbalatma\LaravelJwtAuthentication\Exceptions\InvalidActionException;
use Iqbalatma\LaravelJwtAuthentication\Exceptions\MissingRequiredHeaderException;

class JWTBlacklistService implements \Iqbalatma\LaravelJwtAuthentication\Interfaces\JWTBlacklistService
{
    public string $iat;
    public string $exp;
    public string $tokenType;
    public string|int $sub;
    public string|null $userAgent;

    /**
     * @throws Exception
     */
    public function __construct(public JWTService $jwtService)
    {
        $this->userAgent = request()->userAgent();
        if (!$this->userAgent) {
            throw new MissingRequiredHeaderException("Missing required header User-Agent");
        }

        $this->exp = $this->jwtService->getRequestedExp();
        $this->sub = $this->jwtService->getRequestedSub();
        $this->iat = $this->jwtService->getRequestedIat();
        $this->tokenType = $this->jwtService->getRequestedType();
    }


    /**
     * @param int $incidentTime
     * @return bool
     * @throws InvalidActionException
     */
    public function isTokenBlacklisted(int $incidentTime): bool
    {
        $cachePrefix = JWTService::$JWT_CACHE_KEY_PREFIX;


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
        if (!($issuedTokenBySubject = Cache::get("$cachePrefix.$this->sub"))) {
            Cache::forever("$cachePrefix.$this->sub", collect([]));
            return false;
        }

        /**
         * when user agent, type, and iat greater than current iat exists,
         * it's mean current iat is no longer valid
         * because the valid token is when iat greater than blacklisted iat
         */
        if ($issuedTokenBySubject->where("user_agent", $this->userAgent)
            ->where('type', $this->tokenType)
            ->where('iat', ">", $this->iat)
            ->where("is_blacklisted", true)
            ->first()) {
            return true;
        }

        return false;
    }


    /**
     * @param bool $isBlacklistBothToken
     * @param string|null $userAgent
     * @return void
     * @throws InvalidActionException
     */
    public function blacklistToken(bool $isBlacklistBothToken = false, string|null $userAgent = null): void
    {
        $this->jwtService->setIssuedToken($this->sub);

        if ($isBlacklistBothToken) {
            $this->jwtService->blacklistToken(TokenType::REFRESH->value, $userAgent ?? $this->userAgent);
            $this->jwtService->blacklistToken(TokenType::ACCESS->value, $userAgent ?? $this->userAgent);
        } else {
            $this->jwtService->blacklistToken($this->tokenType, $userAgent ?? $this->userAgent);
        }
    }
}
