<?php

namespace Iqbalatma\LaravelJwtAuthentication\Exceptions;

use Exception;
use Throwable;

class ModelNotCompatibleWithJWTSubjectException extends Exception
{
    public function __construct(string $message = "Your model is not implement Iqbalatma\LaravelJwtAuthentication\Interfaces\JWTSubject", int $code = 0, ?Throwable $previous = null)
    {
        parent::__construct($message, $code, $previous);
    }
}
