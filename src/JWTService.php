<?php

namespace Iqbalatma\LaravelJwtAuthentication;

use App\Models\User;
use Carbon\Carbon;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Str;

class JWTService
{
    private string $secretKey;
    private string $algo;
    private int $accessTokenTTL;
    private int $refreshTTL;
    private array $payload;

    public function __construct()
    {
        $this->secretKey = config("jwt_iqbal.secret");
        $this->algo = config("jwt_iqbal.algo");
        $this->accessTokenTTL = config("jwt_iqbal.access_token_ttl");
        $this->refreshTTL = config("jwt_iqbal.refresh_token_ttl");

        $this->setDefaultPayload();
    }

    private function setDefaultPayload(): void
    {
        $now = time();
        $this->payload = [
            'iss' => url()->current(),
            'iat' => $now,
            'exp' => $now,
            'nbf' => $now,
            'jti' => Str::random(),
            'sub' => null,
        ];
    }

    /**
     * Use to generate jwt from payload
     * @param Authenticatable $authenticatable
     * @return string
     */
    public function generateAccessToken(Authenticatable $authenticatable): string
    {
        $payload = array_merge($this->payload, [
            "exp" => $this->payload["exp"] + $this->accessTokenTTL,
            "sub" => $authenticatable->getAuthIdentifier(),
            "type" => "access",
        ], $authenticatable->getJWTCustomClaims());
        return JWT::encode($payload, $this->secretKey, $this->algo);
    }

    public function generateRefreshToken(Authenticatable $authenticatable): string
    {
        $payload = array_merge($this->payload, [
            "exp" => $this->payload["exp"] + $this->refreshTTL,
            "sub" => $authenticatable->getAuthIdentifier(),
            "type" => "refresh",
        ], $authenticatable->getJWTCustomClaims());
        return JWT::encode($payload, $this->secretKey, $this->algo);
    }


}
