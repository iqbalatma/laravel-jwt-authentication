<?php

return [
    /*
    |--------------------------------------------------------------------------
    | JWT library guard
    |--------------------------------------------------------------------------
    |
    | This is guard that set in auth, because inside library guard defined manually
    | Auth::guard(config("jwt.guard"));
    |
    */
    "guard" => "jwt",


    /*
    |--------------------------------------------------------------------------
    | Access token verifier
    |--------------------------------------------------------------------------
    |
    | This is configuration to prevent xss attack by verified access token via cookie httpOnly
    |
    */
    "is_using_access_token_verifier" => true,

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
    | JWT Private Key
    |--------------------------------------------------------------------------
    |
    | This private key use for first priority of encoding and decoding jwt (signing)
    | so if this key (private key) and (public key) exists, jwt will sign using
    | this key pairs as first priority. If this key pairs does not exist, sign jwt will
    | using jwt secret. If secret does not exist it will throw an error
    |
    */
    "jwt_private_key" => env("JWT_PRIVATE_KEY", null),

    /*
    |--------------------------------------------------------------------------
    | JWT Public Key
    |--------------------------------------------------------------------------
    |
    | This public key is part of key pairs for signing jwt token.
    |
    */
    "jwt_public_key" => env("JWT_PUBLIC_KEY", null),


    /*
    |--------------------------------------------------------------------------
    | JWT Passphrase
    |--------------------------------------------------------------------------
    |
    | This is passphrase use to get jwt private key that translate the key
    | using this passphrase
    |
    */
    "jwt_passphrase" => env("JWT_PASSPHRASE", null),

    /*
    |--------------------------------------------------------------------------
    | Secret
    |--------------------------------------------------------------------------
    |
    | This is secret that used for encoding jwt. This secret use to validate signature
    | Do not expose this jwt secret
    |
    */
    'secret' => env('JWT_SECRET', null),


    /*
    |--------------------------------------------------------------------------
    | Access Token TTL
    |--------------------------------------------------------------------------
    |
    | This is TTL (Time To Life) for access token. When token is expired, the token
    | is already invalid. Access token using to access protected resource.
    | Middleware that can accept this token is auth.jwt:access
    | This TTL is in seconds
    | Default 1 Hour
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
    | This TTL is in seconds
    | Default 7 Days
    */
    'refresh_token_ttl' => env('JWT_REFRESH_TTL', 60 * 60 * 24 * 7),



    /*
    |--------------------------------------------------------------------------
    | Refresh Token
    |--------------------------------------------------------------------------
    |
    | Refresh token mechanism is how middleware check/get your refresh token
    | there are two options (cookie / header)
    |
    |
    | Refresh token key is key to get when middleware mechanism choose cookie, so this key
    | is used to get cookie to set refresh token
    |
    */
    'refresh_token' => [
        'mechanism' => 'cookie', //cookie/header
        'key' => 'jwt_refresh_token',
        'http_only' => true,
        'path' => "/",
        'domain' => null,
        'secure' => true,
        'same_site' => 'lax',
    ],

    /*
    |--------------------------------------------------------------------------
    | Access Token Verifier
    |--------------------------------------------------------------------------
    |
    | Access token verifier is used to prevent XSS attack by binding access token
    | to this verifier, and make sure any stolen token cannot be used by attacker
    |
    |
    */
    'access_token_verifier' => [
        'key' => 'access_token_verifier',
        'http_only' => true,
        'path' => "/",
        'domain' => null,
        'secure' => true,
        'same_site' => 'lax',
    ]
];
