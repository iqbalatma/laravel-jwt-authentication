<?php

namespace Iqbalatma\LaravelJwtAuthentication\Traits;

use Illuminate\Support\Collection;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Cache;
use Iqbalatma\LaravelJwtAuthentication\Contracts\Abstracts\BaseJWTService;
use Iqbalatma\LaravelJwtAuthentication\Exceptions\InvalidActionException;
use Iqbalatma\LaravelJwtAuthentication\Services\JWTService;

trait IssuedTokenHelper
{
    public static string $JWT_CACHE_KEY_PREFIX = "jwt";
    public Collection|null $issuedTokens;
    protected int|string|null $subjectId;

    public function __construct(public JWTService $jwtService)
    {
    }


    /**
     * @param string|int|null $subjectId
     * @return BaseJWTService|IssuedTokenHelper
     * @throws InvalidActionException
     */
    public function setIssuedToken(string|int|null $subjectId = null): self
    {
        $this->subjectId = $subjectId ?: Auth::id();
        if (!$this->subjectId) {
            throw new InvalidActionException("Subject id cannot be null");
        }

        $this->issuedTokens = Cache::get(self::$JWT_CACHE_KEY_PREFIX . ".$this->subjectId") ?? collect();

        return $this;
    }


    /**
     * @param string $tokenType
     * @param string $userAgent
     * @return bool
     */
    private function isIssuedTokenRecordExists(string $tokenType, string $userAgent): bool
    {
        if (!$this->issuedTokens
            ->where("type", $tokenType)
            ->where("user_agent", $userAgent)
            ->first()) {
            return false;
        }

        return true;
    }

    /**
     * @return void
     */
    public function replaceIssuedTokenRecord(): void
    {
        Cache::forever(
            self::$JWT_CACHE_KEY_PREFIX . ".$this->subjectId",
            $this->issuedTokens
        );
    }


    /**
     * @param string $tokenType
     * @param string $userAgent
     * @param bool $isBlacklisted
     * @return void
     */
    private function addNewIssuedToken(string $tokenType, string $userAgent, bool $isBlacklisted = true): void
    {
        $this->issuedTokens = $this->issuedTokens->push([
            "user_agent" => $userAgent,
            "type" => $tokenType,
            "iat" => time(),
            "is_blacklisted" => $isBlacklisted
        ]);
    }

    /**
     * @param string $tokenType
     * @param string $userAgent
     * @param bool $isBlacklist
     * @return BaseJWTService|IssuedTokenHelper
     */
    public function updateIssuedToken(string $tokenType, string $userAgent, bool $isBlacklist = true): self
    {
        $this->issuedTokens = $this->issuedTokens->map(function ($item) use ($tokenType, $userAgent, $isBlacklist) {
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
    public function blacklistToken(string $tokenType, string $userAgent, bool $isBlacklisted = true): void
    {
        $this->isIssuedTokenRecordExists($tokenType, $userAgent) ?
            $this->updateIssuedToken($tokenType, $userAgent, $isBlacklisted) :
            $this->addNewIssuedToken($tokenType, $userAgent, $isBlacklisted);

        $this->replaceIssuedTokenRecord();
    }
}
