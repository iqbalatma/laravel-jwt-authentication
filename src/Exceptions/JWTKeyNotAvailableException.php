<?php

namespace Iqbalatma\LaravelJwtAuthentication\Exceptions;

use Exception;
use Throwable;

class JWTKeyNotAvailableException extends Exception
{
    public function __construct(string $message = "Key not available", int $code = 0, ?Throwable $previous = null)
    {
        parent::__construct($message, $code, $previous);
    }
}
