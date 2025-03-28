<?php

namespace Iqbalatma\LaravelJwtAuthentication\Exceptions;

use Exception;
use Throwable;

class JWTUnauthenticatedUserException extends Exception
{
    public function __construct(string $message = "Your are unauthenticated", int $code = 0, ?Throwable $previous = null)
    {
        parent::__construct($message, $code, $previous);
    }
}
