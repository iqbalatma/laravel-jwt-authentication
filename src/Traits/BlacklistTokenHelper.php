<?php

namespace Iqbalatma\LaravelJwtAuthentication\Traits;

use Illuminate\Support\Collection;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Cache;
use Iqbalatma\LaravelJwtAuthentication\Abstracts\BaseJWTGuard;
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
     * @return BaseJWTGuard|CacheJWTBlacklistService|IssuedTokenService|JWTService|BlacklistTokenHelper
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
     * @param bool $isBlacklist
     * @return BaseJWTGuard|CacheJWTBlacklistService|IssuedTokenService|JWTService|BlacklistTokenHelper
     */
    protected function updateExistingBlacklistTokenByTypeAndUserAgent(string $tokenType, string $userAgent, bool $isBlacklist = true): self
    {
        $this->issuedTokenBySubject = $this->issuedTokenBySubject->map(function ($item) use ($tokenType, $userAgent, $isBlacklist) {
            if ($item["type"] === $tokenType && $item["user_agent"] === $userAgent) {
                $item["iat"] = time();
                $item["is_blacklisted"] = $isBlacklist;
            }
            return $item;
        });

        return $this;
    }


    /**
     * @param string $tokenType
     * @param string $userAgent
     * @param bool $isBlacklisted
     * @return void
     */
    protected function pushNewBlacklistTokenByTypeAndUserAgent(string $tokenType, string $userAgent, bool $isBlacklisted = true): void
    {
        $this->issuedTokenBySubject = $this->issuedTokenBySubject->push([
            "user_agent" => $userAgent,
            "type" => $tokenType,
            "iat" => time(),
            "is_blacklisted" => $isBlacklisted
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
     * @param bool $isBlacklisted
     * @return void
     */
    public function executeBlacklistToken(string $tokenType, string $userAgent, bool $isBlacklisted = true): void
    {
        $this->isTokenBlacklistByTypeAndUserAgentExists($tokenType, $userAgent) ?
            $this->updateExistingBlacklistTokenByTypeAndUserAgent($tokenType, $userAgent, $isBlacklisted) :
            $this->pushNewBlacklistTokenByTypeAndUserAgent($tokenType, $userAgent, $isBlacklisted);

        $this->updateSubjectCacheRecord();
    }
}
