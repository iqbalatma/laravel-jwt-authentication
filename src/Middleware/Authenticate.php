<?php

namespace Iqbalatma\LaravelJwtAuthentication\Middleware;

use Closure;
use Illuminate\Http\Request;
use Iqbalatma\LaravelJwtAuthentication\Abstracts\BaseAuthenticateMiddleware;
use Iqbalatma\LaravelJwtAuthentication\Exceptions\InvalidTokenTypeException;
use Symfony\Component\HttpFoundation\Response;

class Authenticate extends BaseAuthenticateMiddleware
{
    /**
     * Handle an incoming request.
     *
     * @param Closure(Request): (Response) $next
     * @throws InvalidTokenTypeException
     */
    public function handle(Request $request, Closure $next, string $tokenType = "access"): Response
    {
        $this->authenticate($tokenType);
        return $next($request);
    }
}
