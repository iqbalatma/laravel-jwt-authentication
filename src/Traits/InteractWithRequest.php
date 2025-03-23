<?php

namespace Iqbalatma\LaravelJwtAuthentication\Traits;

use Iqbalatma\LaravelJwtAuthentication\Exceptions\JWTMissingRequiredHeaderException;
use Iqbalatma\LaravelJwtAuthentication\Exceptions\JWTMissingRequiredTokenException;
use Iqbalatma\LaravelJwtAuthentication\Middleware\AuthenticateMiddleware;

trait InteractWithRequest
{

    protected string|null $userAgent;
    protected string|null $token;

    /**
     * @param string|null $userAgent
     * @param bool $isRequired
     * @return InteractWithRequest|AuthenticateMiddleware
     * @throws JWTMissingRequiredHeaderException
     */
    protected function setUserAgent(string $userAgent = null, bool $isRequired = true): self
    {
        #check user agent
        if (is_null($userAgent)) {
            if (!($userAgent = $this->request->userAgent()) && $isRequired) {
                throw new JWTMissingRequiredHeaderException("Missing required header User-Agent");
            }
        }
        $this->userAgent = $userAgent;

        return $this;
    }


    /**
     * @return InteractWithRequest
     * @throws JWTMissingRequiredTokenException
     */
    protected function setToken(string $token = null, bool $isRequired = true): self
    {
        if (is_null($token)) {
            if (!$this->request->hasHeader("authorization") && $isRequired) {
                throw new JWTMissingRequiredTokenException();
            }
            $this->token = $this->request->bearerToken();
        }else{
            $this->token = $token;
        }

        return $this;
    }
}
