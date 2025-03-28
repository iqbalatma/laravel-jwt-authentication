<?php

namespace Iqbalatma\LaravelJwtAuthentication\Services;

use Exception;
use Illuminate\Support\Collection;
use Illuminate\Support\Facades\Cache;
use Iqbalatma\LaravelJwtAuthentication\Enums\JWTTokenType;
use Iqbalatma\LaravelJwtAuthentication\Exceptions\JWTInvalidActionException;
use Iqbalatma\LaravelJwtAuthentication\Exceptions\JWTMissingRequiredHeaderException;

class JWTBlacklistService implements \Iqbalatma\LaravelJwtAuthentication\Contracts\Interfaces\JWTBlacklistService
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
            throw new JWTMissingRequiredHeaderException("Missing required header User-Agent");
        }

        $this->exp = $this->jwtService->getRequestedExp();
        $this->sub = $this->jwtService->getRequestedSub();
        $this->iat = $this->jwtService->getRequestedIat();
        $this->tokenType = $this->jwtService->getRequestedType();
    }


    /**
     * @param int|null $incidentTime
     * @return bool
     * @throws JWTInvalidActionException
     */
    public function isTokenBlacklisted(int $incidentTime = null): bool
    {
        if (is_null($incidentTime)) {
            $incidentTime = IncidentTimeService::get();
        }
        $cachePrefix = IssuedTokenService::$JWT_CACHE_KEY_PREFIX;


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
         * @var $issuedTokenCollection Collection
         */
        if (!($issuedTokenCollection = Cache::get("$cachePrefix.$this->sub"))) {
            Cache::forever("$cachePrefix.$this->sub", collect([]));
            return false;
        }

        /**
         * when user agent, type, and iat greater than current iat exists,
         * it's mean current iat is no longer valid
         * because the valid token is when iat greater than blacklisted iat
         */
        if (
            $issuedTokenCollection->where("user_agent", $this->userAgent)
                ->where('type', $this->tokenType)
                ->where('iat', ">", $this->iat)
                ->first() ||
            $issuedTokenCollection->where("user_agent", $this->userAgent)
                ->where('type', $this->tokenType)
                ->where("is_blacklisted", true)
                ->first()
        ) {
            return true;
        }

        return false;
    }


    /**
     * @param bool $isBlacklistBothToken
     * @param string|null $userAgent
     * @return void
     * @throws JWTInvalidActionException
     */
    public function blacklistToken(bool $isBlacklistBothToken = false, string|null $userAgent = null): void
    {
        $issuedTokenService = IssuedTokenService::build()
            ->setIssuedTokenCollection($this->sub);

        $userAgent = $userAgent ?? $this->userAgent;
        if ($isBlacklistBothToken) {
            $issuedTokenService->isExists(JWTTokenType::REFRESH, $userAgent) ?
                $issuedTokenService->updateIssuedToken(JWTTokenType::REFRESH, $userAgent) :
                $issuedTokenService->addNewIssuedToken(JWTTokenType::REFRESH, $userAgent);

            $issuedTokenService->isExists(JWTTokenType::ACCESS, $userAgent) ?
                $issuedTokenService->updateIssuedToken(JWTTokenType::ACCESS, $userAgent) :
                $issuedTokenService->addNewIssuedToken(JWTTokenType::ACCESS, $userAgent);
        } else {
            $issuedTokenService->isExists(JWTTokenType::{$this->tokenType}, $userAgent) ?
                $issuedTokenService->updateIssuedToken(JWTTokenType::{$this->tokenType}, $userAgent) :
                $issuedTokenService->addNewIssuedToken(JWTTokenType::{$this->tokenType}, $userAgent);
        }

        $issuedTokenService->refreshIssuedTokenCollection($this->sub);
    }
}
