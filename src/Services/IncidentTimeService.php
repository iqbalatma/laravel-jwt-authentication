<?php

namespace Iqbalatma\LaravelJwtAuthentication\Services;

use Illuminate\Support\Facades\Cache;

class IncidentTimeService
{
    public const string LATEST_INCIDENT_TIME_KEY = "jwt.latest_incident_date_time";

    /**
     * @description first initiate last incident time
     * this use when redis data is reset, but you already invoke many token,
     * you can invalidate all issued token, and make user re-logged in
     * @return void
     */
    public static function check(): void
    {
        if (!Cache::get(self::LATEST_INCIDENT_TIME_KEY)) {
            $now = time();
            Cache::forever(self::LATEST_INCIDENT_TIME_KEY, $now - 1);
        }
    }

    /**
     * @description get incident time
     * @return int
     */
    public static function get(): int
    {
        self::check();

        return Cache::get(self::LATEST_INCIDENT_TIME_KEY);
    }
}
