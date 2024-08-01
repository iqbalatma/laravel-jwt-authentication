<?php

namespace Iqbalatma\LaravelJwtAuthentication\Traits;

use Illuminate\Support\Collection;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Cache;
use Iqbalatma\LaravelJwtAuthentication\Abstracts\BaseJWTService;
use Iqbalatma\LaravelJwtAuthentication\Exceptions\InvalidActionException;
use Iqbalatma\LaravelJwtAuthentication\Exceptions\MissingRequiredHeaderException;
use Iqbalatma\LaravelJwtAuthentication\Exceptions\MissingRequiredTokenException;
use Iqbalatma\LaravelJwtAuthentication\Middleware\AuthenticateMiddleware;
use Iqbalatma\LaravelJwtAuthentication\Services\JWTService;

trait InteractWithRequest
{

    protected string|null $userAgent;
    protected string|null $token;

    /**
     * @param string|null $userAgent
     * @param bool $isRequired
     * @return InteractWithRequest
     * @throws MissingRequiredHeaderException
     */
    protected function setUserAgent(string $userAgent = null, bool $isRequired = true): self
    {
        #check user agent
        if (is_null($userAgent)) {
            if (!($userAgent = $this->request->userAgent()) && $isRequired) {
                throw new MissingRequiredHeaderException("Missing required header User-Agent");
            }
        }
        $this->userAgent = $userAgent;

        return $this;
    }


    /**
     * @return InteractWithRequest
     * @throws MissingRequiredTokenException
     */
    protected function setToken(string $token = null, bool $isRequired = true): self
    {
        if (is_null($token)) {
            if (!$this->request->hasHeader("authorization") && $isRequired) {
                throw new MissingRequiredTokenException();
            }
            $this->token = $this->request->bearerToken();
        }else{
            $this->token = $token;
        }

        return $this;
    }
}
