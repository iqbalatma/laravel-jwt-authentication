<?php


use Illuminate\Support\Facades\Cookie;

if (!function_exists("getJWTRefreshTokenMechanism")) {
    /**
     * @return string
     */
    function getJWTRefreshTokenMechanism(): string
    {
        $mechanism = config("jwt.refresh_token.mechanism");
        if (!in_array($mechanism, ["cookie", "header"])) {
            throw new RuntimeException("Mechanism '{$mechanism}' not supported");
        }
        return config("jwt.refresh_token.mechanism");
    }
}

if (!function_exists("getRefreshTokenTTLInMinutes")) {
    /**
     * since token ttl in config in seconds, we need to transform into minutes
     * @return int
     */
    function getRefreshTokenTTLInMinutes(): int
    {
        return config("jwt.refresh_token_ttl") / 60;
    }
}


if (!function_exists("getCreatedCookieRefreshToken")) {
    /**
     * @param string $value
     * @return \Symfony\Component\HttpFoundation\Cookie
     */
    function getCreatedCookieRefreshToken(string $value): \Symfony\Component\HttpFoundation\Cookie
    {
        return Cookie::make(
            name: config("jwt.refresh_token.key"),
            value: $value,
            minutes: getRefreshTokenTTLInMinutes(),
            path: config("jwt.refresh_token.path"),
            domain: config("jwt.refresh_token.domain"),
            secure: config("jwt.refresh_token.secure"),
            httpOnly: config("jwt.refresh_token.http_only"),
            raw: false,
            sameSite: config("jwt.refresh_token.same_site"),
        );
    }
}


if (!function_exists("getCreatedCookieAccessTokenVerifier")) {
    /**
     * @param string $value
     * @return \Symfony\Component\HttpFoundation\Cookie
     */
    function getCreatedCookieAccessTokenVerifier(string $value): \Symfony\Component\HttpFoundation\Cookie
    {
        return Cookie::make(
            name: config("jwt.access_token_verifier.key"),
            value: $value,
            minutes: getRefreshTokenTTLInMinutes(),
            path: config("jwt.access_token_verifier.path"),
            domain: config("jwt.access_token_verifier.domain"),
            secure: config("jwt.access_token_verifier.secure"),
            httpOnly: config("jwt.access_token_verifier.http_only"),
            raw: false,
            sameSite: config("jwt.access_token_verifier.same_site"),
        );
    }
}



