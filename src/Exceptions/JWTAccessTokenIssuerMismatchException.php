<?php

namespace Iqbalatma\LaravelJwtAuthentication\Exceptions;

use Exception;
use Throwable;

class JWTAccessTokenIssuerMismatchException extends Exception
{
    public function __construct(string $message = "Your access token is not verified because your access token verifier is missing or mismatch. Could be because this token has been stolen and will be revoked immediately", int $code = 0, ?Throwable $previous = null)
    {
        parent::__construct($message, $code, $previous);
    }
}
