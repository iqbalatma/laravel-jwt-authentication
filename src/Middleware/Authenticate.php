<?php

namespace Iqbalatma\LaravelJwtAuthentication\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Symfony\Component\HttpFoundation\Response;

class Authenticate extends BaseAuthenticateMiddleware
{
    /**
     * Handle an incoming request.
     *
     * @param Closure(Request): (Response) $next
     */
    public function handle(Request $request, Closure $next, string $tokenType = "access"): Response
    {
        $this->authenticate($tokenType);
        return $next($request);
    }
}
