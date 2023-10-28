<?php

namespace Iqbalatma\LaravelJwtAuthentication\Interfaces;

interface JWTBlacklistService
{
    public function isTokenBlacklisted(int $incidentTime):bool;
    public function blacklistToken(bool $isBlacklistBothToken = false):void;
}
