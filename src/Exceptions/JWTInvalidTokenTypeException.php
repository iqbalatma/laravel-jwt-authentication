<?php

namespace Iqbalatma\LaravelJwtAuthentication\Exceptions;

use Exception;
use Throwable;

class JWTInvalidTokenTypeException extends Exception
{
    public function __construct(string $message = "Your token type is invalid. Available token type only access and refresh token", int $code = 0, ?Throwable $previous = null)
    {
        parent::__construct($message, $code, $previous);
    }
}
