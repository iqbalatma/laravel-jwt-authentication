<?php

namespace Iqbalatma\LaravelJwtAuthentication\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Iqbalatma\LaravelJwtAuthentication\Exceptions\InvalidTokenException;
use Iqbalatma\LaravelJwtAuthentication\Exceptions\MissingRequiredTokenException;
use Iqbalatma\LaravelJwtAuthentication\JWTService;
use Symfony\Component\HttpFoundation\Response;

class BaseAuthenticateMiddleware
{
    protected string $token;

    /**
     * @throws MissingRequiredTokenException|InvalidTokenException
     */
    public function __construct(protected JWTService $jwtService, protected readonly Request $request)
    {
        $this->setToken()
            ->checkIsTokenValid();
        //check is token access type
        //check is token blacklisted
        //login via id
    }

    protected function authenticate()
    {
        ddapi($this->jwtService->getRequestedPayload());
    }


    /**
     * @return self
     * @throws MissingRequiredTokenException
     */
    private function setToken(): self
    {
        if (!$this->request->hasHeader("authorization")) {
            throw new MissingRequiredTokenException();
        }
        $this->token = $this->request->bearerToken();
        return $this;
    }


    /**
     * @return self
     * @throws InvalidTokenException
     */
    private function checkIsTokenValid():self
    {
        try {
            $this->jwtService->decodeJWT($this->token);
        }catch (\Exception $e){
            throw new InvalidTokenException();
        }

        return $this;
    }
}
