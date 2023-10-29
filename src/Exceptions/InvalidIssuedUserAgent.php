<?php

namespace Iqbalatma\LaravelJwtAuthentication\Exceptions;

use Exception;
use Throwable;

class InvalidIssuedUserAgent extends Exception
{
    public function __construct(string $message = "This token cannot be used in different issued user agent", int $code = 0, ?Throwable $previous = null)
    {
        parent::__construct($message, $code, $previous);
    }
}
