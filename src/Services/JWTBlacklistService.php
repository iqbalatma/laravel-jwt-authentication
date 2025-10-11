<?php

namespace Iqbalatma\LaravelJwtAuthentication\Services;

use Carbon\Carbon;
use Exception;
use Illuminate\Support\Facades\Cache;
use Iqbalatma\LaravelJwtAuthentication\Enums\JWTTokenType;
use Iqbalatma\LaravelJwtAuthentication\Exceptions\JWTInvalidActionException;
use Iqbalatma\LaravelUtils\Exceptions\DumpAPIException;

class JWTBlacklistService implements \Iqbalatma\LaravelJwtAuthentication\Interfaces\JWTBlacklistService
{
    /**
     * @throws Exception
     */
    public function __construct(public DecodingService $decodingService)
    {
    }


    /**
     * @param int|null $incidentTime
     * @return bool
     * @throws JWTInvalidActionException
     * @throws DumpAPIException
     */
    public function isTokenBlacklisted(int $incidentTime = null): bool
    {
        if (is_null($incidentTime)) {
            $incidentTime = IncidentTimeService::get();
        }
        /**
         * this is condition when redis got incident, and latest incident date time is updated and reset
         * so when token is below incident date time, it's mean there is possibility that token already on blacklist
         * but since redis got incident and deleted, it will be considered as valid token
         * so, we need to check if incident time is greater or equal than iat
         */
        if ($incidentTime >= $this->decodingService->getRequestedIat()) {
            $this->blacklistToken(true);
            return true;
        }


        /** JTI already exist on blacklist token */
        if (Cache::get((string)($this->decodingService->getRequestedJti()))) {
            return true;
        }

        return false;
    }


    /**
     * @param bool $isBlacklistBothToken
     * @return void
     */
    public function blacklistToken(bool $isBlacklistBothToken = false): void
    {
        if ($isBlacklistBothToken) {
            $timeLeft = $this->decodingService->getRequestedType() === JWTTokenType::ACCESS->name ?
                $this->decodingService->accessTokenTTL :
                $this->decodingService->refreshTokenTTL;
            if ($timeLeft > 0) {
                Cache::put($this->decodingService->getRequestedPti(), true, $timeLeft);
            }
        }

        $timeLeft = (int)$this->decodingService->getRequestedExp() - Carbon::now()->timestamp;
        if ($timeLeft > 0) {
            Cache::put($this->decodingService->getRequestedJti(), true, $timeLeft);
        }

    }
}
