<?php

namespace Iqbalatma\LaravelJwtAuthentication\Interfaces;

interface JWTBlacklistService
{
    public function isTokenBlacklisted():bool;
    public function blacklistToken();
}
