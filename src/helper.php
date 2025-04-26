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


if (!function_exists("getCreatedCookie")) {
    /**
     * @param string $value
     * @return \Symfony\Component\HttpFoundation\Cookie
     */
    function getCreatedCookie(string $value): \Symfony\Component\HttpFoundation\Cookie
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



