<?php

namespace Iqbalatma\LaravelJwtAuthentication\Abstracts;

abstract class BaseJWTService
{
    /**
     * @return string
     */
    public function getRequestedIat(): string
    {
        return $this->getRequestedTokenPayloads("iat");
    }

    abstract public function getRequestedTokenPayloads(null|string $key = null): string|array;
}
