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

    /**
     * @return string
     */
    public function getRequestedSub(): string
    {
        return $this->getRequestedTokenPayloads("sub");
    }

    public function getRequestedType(): string
    {
        return $this->getRequestedTokenPayloads("type");
    }

    abstract public function getRequestedTokenPayloads(null|string $key = null): string|array;
}
