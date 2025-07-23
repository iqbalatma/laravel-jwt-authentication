<?php

namespace Iqbalatma\LaravelJwtAuthentication\Services;

use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use Illuminate\Support\Str;
use Iqbalatma\LaravelJwtAuthentication\Contracts\Abstracts\BaseJWTService;
use Iqbalatma\LaravelJwtAuthentication\Contracts\Interfaces\JWTSubject;
use Iqbalatma\LaravelJwtAuthentication\Enums\JWTTokenType;
use Iqbalatma\LaravelJwtAuthentication\Exceptions\JWTInvalidActionException;
use RuntimeException;
use stdClass;

class JWTService extends BaseJWTService
{
    /**
     * @param JWTTokenType $type
     * @param JWTSubject $user
     * @return string
     * @throws JWTInvalidActionException
     */
    public function generateToken(JWTTokenType $type, JWTSubject $user): string
    {
        $this->setDefaultPayload();
        $ttl = $type === JWTTokenType::ACCESS ?
            $this->accessTokenTTL : $this->refreshTokenTTL;

        $payload = array_merge(
            $this->payload,
            [
                "exp" => $this->payload["exp"] + $ttl,
                "sub" => $user->getAuthIdentifier(),
                "type" => $type->name,
                "atv" => $type->name === JWTTokenType::ACCESS->name ? Str::uuid() : null
            ],
            $user->getJWTCustomClaims()
        );


        #use to register generated token to issued token by subject collection
        $issuedTokenService = IssuedTokenService::build()
            ->setIssuedTokenCollection($user->getJWTIdentifier());

        $issuedTokenService->isExists($type, $this->userAgent) ?
            $issuedTokenService->updateIssuedToken($type, $this->userAgent, false, $user->getJWTIdentifier()) :
            $issuedTokenService->addNewIssuedToken($type, $this->userAgent, false, $user->getJWTIdentifier());

        return JWT::encode($payload, $this->jwtKey->getPrivateKey(), $this->jwtKey->getAlgo());
    }


    /**
     * @param string $token
     * @return array
     */
    public function decodeJWT(string $token): array
    {
        $headers = new stdClass();
        $this->requestTokenPayloads = (array)JWT::decode($token, new Key($this->jwtKey->getPublicKey(), $this->jwtKey->getAlgo()), $headers);
        $this->requestTokenHeaders = $headers;

        return $this->requestTokenPayloads;
    }


    /**
     * @param string|null $key
     * @return string|array
     */
    public function getRequestedTokenPayloads(null|string $key = null): string|array
    {
        if (!isset($this->requestTokenPayloads)) {
            throw new RuntimeException("Token payloads are not set.");
        }

        if ($key) {
            if (isset($this->requestTokenPayloads[$key])) {
                return $this->requestTokenPayloads[$key];
            }

            throw new RuntimeException("Undefined array key $key");
        }

        return $this->requestTokenPayloads;
    }


    /**
     * @param string|null $key
     * @return string|array
     */
    public function getRequestTokenHeaders(null|string $key = null): string|array
    {
        $headers = (array)$this->requestTokenHeaders;
        if ($key) {
            if (isset($headers[$key])) {
                return $headers[$key];
            }

            throw new RuntimeException("Undefined array key $key");
        }
        return $headers;
    }
}
