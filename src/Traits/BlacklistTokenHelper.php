<?php

namespace Iqbalatma\LaravelJwtAuthentication\Traits;

use Illuminate\Support\Collection;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Cache;
use Iqbalatma\LaravelJwtAuthentication\CacheJWTBlacklistService;
use Iqbalatma\LaravelJwtAuthentication\Exceptions\InvalidActionException;
use Iqbalatma\LaravelJwtAuthentication\IssuedTokenService;
use Iqbalatma\LaravelJwtAuthentication\JWTService;

trait BlacklistTokenHelper
{
    protected static string $jwtKeyPrefix = "jwt";

    protected Collection|null $issuedTokenBySubject;
    protected int|string|null $subjectId;

    /**
     * @param string|int|null $subjectId
     * @return JWTService|CacheJWTBlacklistService|IssuedTokenService|BlacklistTokenHelper
     * @throws InvalidActionException
     */
    protected function setSubjectCacheRecord(string|int|null $subjectId = null): self
    {
        $this->subjectId = $subjectId ?: Auth::id();
        if (!$this->subjectId) {
            throw new InvalidActionException("Subject id cannot be null");
        }

        $this->issuedTokenBySubject = Cache::get(self::$jwtKeyPrefix . ".$this->subjectId") ?? collect();

        return $this;
    }


    /**
     * @param string $tokenType
     * @param string $userAgent
     * @return bool
     */
    protected function isTokenBlacklistByTypeAndUserAgentExists(string $tokenType, string $userAgent): bool
    {
        if (!$this->issuedTokenBySubject->where("type", $tokenType)
            ->where("user_agent", $userAgent)
            ->first()) {
            return false;
        }

        return true;
    }


    /**
     * @param string $tokenType
     * @param string $userAgent
     * @param int|null $iat
     * @return JWTService|CacheJWTBlacklistService|IssuedTokenService|BlacklistTokenHelper
     */
    protected function updateExistingBlacklistTokenByTypeAndUserAgent(string $tokenType, string $userAgent, null|int $iat = null): self
    {
        if (!$iat) {
            $iat = time();
        }
        $this->issuedTokenBySubject = $this->issuedTokenBySubject->map(function ($item) use ($tokenType, $userAgent, $iat) {
            if ($item["type"] === $tokenType && $item["user_agent"] === $userAgent) {
                $item["iat"] = $iat;
            }
            return $item;
        });

        return $this;
    }


    /**
     * @param string $tokenType
     * @param string $userAgent
     * @param int|null $iat
     * @return void
     */
    protected function pushNewBlacklistTokenByTypeAndUserAgent(string $tokenType, string $userAgent, null|int $iat = null): void
    {
        if (!$iat) {
            $iat = time();
        }
        $this->issuedTokenBySubject = $this->issuedTokenBySubject->push([
            "user_agent" => $userAgent,
            "type" => $tokenType,
            "iat" => $iat
        ]);
    }


    /**
     * @return void
     */
    protected function updateSubjectCacheRecord(): void
    {
        Cache::forever(self::$jwtKeyPrefix . ".$this->subjectId", $this->issuedTokenBySubject);
    }


    /**
     * @param string $tokenType
     * @param string $userAgent
     * @param int|null $iat
     * @return void
     */
    public function executeBlacklistToken(string $tokenType, string $userAgent, int|null $iat = null): void
    {
        if (!$iat) {
            $iat = time();
        }

        $this->isTokenBlacklistByTypeAndUserAgentExists($tokenType, $userAgent) ?
            $this->updateExistingBlacklistTokenByTypeAndUserAgent($tokenType, $userAgent, $iat) :
            $this->pushNewBlacklistTokenByTypeAndUserAgent($tokenType, $userAgent, $iat);

        $this->updateSubjectCacheRecord();
    }
}
