<?php

namespace Iqbalatma\LaravelJwtAuthentication\Contracts\Interfaces;

interface JWTBlacklistService
{
    public function isTokenBlacklisted(int $incidentTime): bool;

    public function blacklistToken(bool $isBlacklistBothToken = false, string|null $userAgent = null): void;
}
