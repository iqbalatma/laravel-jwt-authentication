<?php

namespace Iqbalatma\LaravelJwtAuthentication\Exceptions;

use Exception;
use Throwable;

class JWTInvalidTokenException extends Exception
{
    public function __construct(string $message = "Your request token is expired or invalid", int $code = 0, ?Throwable $previous = null)
    {
        parent::__construct($message, $code, $previous);
    }
}
