<?php

namespace Iqbalatma\LaravelJwtAuthentication\Exceptions;

use Exception;
use Iqbalatma\LaravelJwtAuthentication\Contracts\Interfaces\JWTSubject;
use Throwable;

class JWTModelNotCompatibleWithJWTSubjectException extends Exception
{
    public function __construct(string $message = "Your model is not implement " . JWTSubject::class, int $code = 0, ?Throwable $previous = null)
    {
        parent::__construct($message, $code, $previous);
    }
}
