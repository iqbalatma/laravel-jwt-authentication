<?php

namespace Iqbalatma\LaravelJwtAuthentication\Services;

use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use Iqbalatma\LaravelJwtAuthentication\Abstracts\BaseJWTService;
use Iqbalatma\LaravelJwtAuthentication\Enums\JWTTokenType;
use Iqbalatma\LaravelJwtAuthentication\Exceptions\JWTInvalidActionException;
use Iqbalatma\LaravelJwtAuthentication\Exceptions\JWTMissingRequiredHeaderException;
use Iqbalatma\LaravelJwtAuthentication\Interfaces\JWTSubject;
use Iqbalatma\LaravelJwtAuthentication\Payload;
use RuntimeException;
use stdClass;

class JWTService extends BaseJWTService
{
    /**
     * @param JWTTokenType $type
     * @param JWTSubject $user
     * @param string|null $atv
     * @param bool $isUsingCookie
     * @return string
     * @throws JWTInvalidActionException
     * @throws JWTMissingRequiredHeaderException
     */
    public function generateToken(JWTTokenType $type, JWTSubject $user, string|null $atv = null, bool $isUsingCookie = true): string
    {
        IncidentTimeService::check();
        $this->payload = (new Payload($type))
            ->addExpTTL($type === JWTTokenType::ACCESS ?
                $this->accessTokenTTL : $this->refreshTokenTTL
            )
            ->setSub($user->getAuthIdentifier())
            ->setIuc($isUsingCookie)
            ->setAtv($atv);

        #use to register generated token to issued token by subject collection
        $issuedTokenService = IssuedTokenService::build()
            ->setIssuedTokenCollection($user->getJWTIdentifier());

        $issuedTokenService->isExists($type, $this->userAgent) ?
            $issuedTokenService->updateIssuedToken($type, $this->userAgent, false, $user->getJWTIdentifier()) :
            $issuedTokenService->addNewIssuedToken($type, $this->userAgent, false, $user->getJWTIdentifier());

        return JWT::encode(array_merge($this->payload->toArray(), $user->getJWTCustomClaims()), $this->jwtKey->getPrivateKey(), $this->jwtKey->getAlgo());
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
