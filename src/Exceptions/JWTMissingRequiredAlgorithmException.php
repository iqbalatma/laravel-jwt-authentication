<?php

namespace Iqbalatma\LaravelJwtAuthentication\Exceptions;

use Exception;
use Throwable;

class JWTMissingRequiredAlgorithmException extends Exception
{
    public function __construct(string $message = "You are not set jwt algorithm yet", int $code = 0, ?Throwable $previous = null)
    {
        parent::__construct($message, $code, $previous);
    }
}
