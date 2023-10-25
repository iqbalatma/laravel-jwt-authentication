<?php

namespace Iqbalatma\LaravelJwtAuthentication;

use Exception;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Support\Str;
use Iqbalatma\LaravelJwtAuthentication\Exceptions\ModelNotCompatibleWithJWTSubjectException;
use Iqbalatma\LaravelJwtAuthentication\Interfaces\JWTSubject;

class JWTService
{
    private string $secretKey;
    private string $algo;
    private int $accessTokenTTL;
    private int $refreshTTL;
    private array $payload;
    private array $requestedPayload;

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
     * @param Authenticatable $authenticatable
     * @return string
     * @throws ModelNotCompatibleWithJWTSubjectException
     */
    public function generateAccessToken(Authenticatable $authenticatable): string
    {
        $this->checkAuthenticatableContracts($authenticatable);

        $payload = array_merge($this->payload, [
            "exp" => $this->payload["exp"] + $this->accessTokenTTL,
            "sub" => $authenticatable->getAuthIdentifier(),
            "type" => "access",
        ], $authenticatable->getJWTCustomClaims());
        return JWT::encode($payload, $this->secretKey, $this->algo);
    }


    /**
     * @param Authenticatable $authenticatable
     * @return string
     * @throws ModelNotCompatibleWithJWTSubjectException
     */
    public function generateRefreshToken(Authenticatable $authenticatable): string
    {
        $this->checkAuthenticatableContracts($authenticatable);

        $payload = array_merge($this->payload, [
            "exp" => $this->payload["exp"] + $this->refreshTTL,
            "sub" => $authenticatable->getAuthIdentifier(),
            "type" => "refresh",
        ], $authenticatable->getJWTCustomClaims());
        return JWT::encode($payload, $this->secretKey, $this->algo);
    }


    /**
     * @param Authenticatable $authenticatable
     * @return void
     * @throws ModelNotCompatibleWithJWTSubjectException
     */
    private function checkAuthenticatableContracts(Authenticatable $authenticatable): void
    {
        if (!$authenticatable instanceof JWTSubject) {
            throw new ModelNotCompatibleWithJWTSubjectException();
        }
    }


    /**
     * @param string $token
     * @return array
     */
    public function decodeJWT(string $token):array
    {
        $this->requestedPayload = (array) JWT::decode($token, new Key($this->secretKey, $this->algo));
        return $this->requestedPayload;
    }


    /**
     * @param string|null $key
     * @return string|array
     * @throws Exception
     */
    public function getRequestedPayload(null|string $key = null):string|array
    {
        if ($key){
            if (isset($this->requestedPayload[$key])){
                return $this->requestedPayload[$key];
            }else{
                throw new Exception("Undefined array key $key");
            }
        }
        return $this->requestedPayload;
    }
}
