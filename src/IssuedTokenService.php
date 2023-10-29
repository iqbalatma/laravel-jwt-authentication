<?php

namespace Iqbalatma\LaravelJwtAuthentication;

use Exception;
use Illuminate\Support\Collection;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Cache;
use Iqbalatma\LaravelJwtAuthentication\Enums\TokenType;
use Iqbalatma\LaravelJwtAuthentication\Exceptions\EntityDoesNotExistsException;
use Iqbalatma\LaravelJwtAuthentication\Exceptions\InvalidActionException;
use Iqbalatma\LaravelJwtAuthentication\Traits\BlacklistTokenHelper;

class IssuedTokenService
{
    use BlacklistTokenHelper;

    protected Collection $tokenRecords;
    protected string|int|null $requestSubjectId;

    public function __construct(public JWTService $jwtService)
    {
    }

    /**
     * @param string|int|null $requestSubjectId
     * @return IssuedTokenService
     * @throws InvalidActionException
     */
    protected function setRequestSubjectId(string|int|null $requestSubjectId): self
    {
        $this->requestSubjectId = $requestSubjectId ?: Auth::id();
        if (!$this->requestSubjectId) {
            throw new InvalidActionException("Subject id cannot be null");
        }

        return $this;
    }

    /**
     * @return void
     */
    protected function setTokenRecord(): void
    {
        $this->tokenRecords = Cache::get(self::$jwtKeyPrefix . ".$this->requestSubjectId") ?: collect([]);
    }


    /**
     * @param string|int|null $requestSubjectId
     * @return Collection
     * @throws InvalidActionException
     */
    public static function getAllToken(string|int|null $requestSubjectId = null): Collection
    {
        $instance = (new static());
        $instance->setRequestSubjectId($requestSubjectId)
            ->setTokenRecord();

        return $instance->tokenRecords->filter(function ($item) use($instance) {
            return $item["iat"] < $instance->jwtService->getRequestedTokenPayloads("iat");
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


    /**
     * @param string $userAgent
     * @param string|int|null $subjectId
     * @return void
     * @throws EntityDoesNotExistsException
     */
    public static function revokeTokenRefreshByUserAgent(string $userAgent, string|int|null $subjectId = null): void
    {
        /**
         * todo: this line of code can move into single method
         */
        if (!$subjectId) {
            $subjectId = Auth::id();
        }

        $instance = (new static());
        $instance->setSubjectCacheRecord($subjectId);

        if (!$instance->isTokenBlacklistByTypeAndUserAgentExists(TokenType::REFRESH->value, $userAgent)) {
            throw new EntityDoesNotExistsException("Token on device $userAgent does not exists");
        }

        $instance->updateExistingBlacklistTokenByTypeAndUserAgent(TokenType::REFRESH->value, $userAgent);
        $instance->updateSubjectCacheRecord($subjectId);
    }

    /**
     * @param string $userAgent
     * @param string|int|null $subjectId
     * @return void
     * @throws EntityDoesNotExistsException
     */
    public static function revokeTokenAccessByUserAgent(string $userAgent, string|int|null $subjectId = null): void
    {
        /**
         * todo: this line of code can move into single method
         */
        if (!$subjectId) {
            $subjectId = Auth::id();
        }

        $instance = (new static());
        $instance->setSubjectCacheRecord($subjectId);

        if (!$instance->isTokenBlacklistByTypeAndUserAgentExists(TokenType::ACCESS->value, $userAgent)) {
            throw new EntityDoesNotExistsException("Token on device $userAgent does not exists");
        }

        $instance->updateExistingBlacklistTokenByTypeAndUserAgent(TokenType::ACCESS->value, $userAgent);
        $instance->updateSubjectCacheRecord($subjectId);
    }


    /**
     * @throws EntityDoesNotExistsException
     */
    public static function revokeTokenByUserAgent(string $userAgent, string|int|null $subjectId = null): void
    {
        if (!$subjectId) {
            $subjectId = Auth::id();
        }
        self::revokeTokenAccessByUserAgent($userAgent, $subjectId);
        self::revokeTokenRefreshByUserAgent($userAgent, $subjectId);
    }
}
