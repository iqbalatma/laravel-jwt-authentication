<?php

namespace Iqbalatma\LaravelJwtAuthentication\Middleware;

use Closure;
use Exception;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Iqbalatma\LaravelJwtAuthentication\Exceptions\InvalidTokenException;
use Iqbalatma\LaravelJwtAuthentication\Exceptions\InvalidTokenTypeException;
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


    /**
     * @param string $tokenType
     * @return void
     * @throws InvalidTokenTypeException
     */
    protected function authenticate(string $tokenType): void
    {
        $this->checkTokenType($tokenType);
    }

    /**
     * @param string $tokenType
     * @return void
     * @throws InvalidTokenTypeException
     * @throws Exception
     */
    private function checkTokenType(string $tokenType): void
    {
        if (strtolower($tokenType) !== "access" && strtolower($tokenType) !== "refresh") {
            throw new InvalidTokenTypeException();
        }


        /**
         * check condition when requested token type is different with middleware token type
         */
        if (($requestedTokenType = $this->jwtService->getRequestedTokenPayloads("type")) !== $tokenType) {
            throw new InvalidTokenTypeException("This protected resource need token type $tokenType, but you provide $requestedTokenType");
        }
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
     * @return void
     * @throws InvalidTokenException
     */
    private function checkIsTokenValid(): void
    {
        try {
            $this->jwtService->decodeJWT($this->token);
        } catch (Exception $e) {
            throw new InvalidTokenException();
        }
    }
}
