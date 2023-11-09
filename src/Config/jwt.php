<?php

return [
    /*
        |--------------------------------------------------------------------------
        | JWT Sign in Algorithm
        |--------------------------------------------------------------------------
        |
        | Algorithm for sign jwt token. This token is using encoder and decoder from
        | https://github.com/firebase/php-jwt
        |
        */
    'algo' => env('JWT_ALGO', 'HS256'),


    /*
    |--------------------------------------------------------------------------
    | Secret
    |--------------------------------------------------------------------------
    |
    | This is secret that used for encoding jwt. This secret use to validate signature
    | Do not expose this jwt secret
    |
    */
    'secret' => env('JWT_SECRET'),


    /*
    |--------------------------------------------------------------------------
    | Access Token TTL
    |--------------------------------------------------------------------------
    |
    | This is TTL (Time To Life) for access token. When token is expired, the token
    | is already invalid. Access token using to access protected resource.
    | Middleware that can accept this token is auth.jwt:access
    |
    */
    'access_token_ttl' => env('JWT_TTL', 60 * 60),

    /*
    |--------------------------------------------------------------------------
    | Refresh Token TTL
    |--------------------------------------------------------------------------
    |
    | This is TTL (Time To Life) for refresh token. When token is expired, the token
    | is already invalid. Refresh token using to regenerate access token and refresh token
    | and revoke previous access token and refresh token.
    | Middleware that can accept this token is auth.jwt:refresh
    |
    */
    'refresh_token_ttl' => env('JWT_REFRESH_TTL', 60 * 60 * 24 * 7),

    /*
    |--------------------------------------------------------------------------
    | Incident Time Key
    |--------------------------------------------------------------------------
    |
    | Since we using cache for blacklist token, there is possibility for cache like
    | redis got an incident and lost all blacklist record. When that happened we
    | will invalidate all token before now
    | This key is to set incident date time on cache
    |
    */
    'latest_incident_time_key' => "jwt.latest_incident_date_time",


    "jwt_private_key" => env("JWT_PRIVATE_KEY", null),
    "jwt_public_key" => env("JWT_PUBLIC_KEY", null),
    "jwt_passphrase" => env("JWT_PASSPHRASE", null),

];
