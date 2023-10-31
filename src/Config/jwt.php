<?php

return [
    'algo' => env('JWT_ALGO', 'HS256'),
    'secret' => env('JWT_SECRET'),
    'access_token_ttl' => env('JWT_TTL', 60 * 60),
    'refresh_token_ttl' => env('JWT_REFRESH_TTL', 60 * 60 * 24 * 7),
    'latest_incident_time_key' => "jwt.latest_incident_date_time"
];
