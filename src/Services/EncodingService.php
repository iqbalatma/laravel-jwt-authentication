<?php

namespace Iqbalatma\LaravelJwtAuthentication\Services;

use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use Iqbalatma\LaravelJwtAuthentication\Enums\JWTTokenType;
use Iqbalatma\LaravelJwtAuthentication\Exceptions\JWTMissingRequiredHeaderException;
use Iqbalatma\LaravelJwtAuthentication\Interfaces\JWTKey;
use Iqbalatma\LaravelJwtAuthentication\Interfaces\JWTSubject;
use Iqbalatma\LaravelJwtAuthentication\Payload;
use RuntimeException;
use stdClass;

class EncodingService extends BaseJWTService
{

    protected Payload $payload;

    /**
     * @param JWTTokenType $type
     * @param JWTSubject $user
     * @param string|null $atv
     * @param bool $isUsingCookie
     * @param string|null $jti
     * @param string|null $pti
     * @return string
     * @throws JWTMissingRequiredHeaderException
     */
    public function generateToken(
        JWTTokenType $type,
        JWTSubject $user,
        string|null $atv = null,
        bool $isUsingCookie = true,
        string|null $jti = null,
        string|null $pti = null,
    ): string
    {
        IncidentTimeService::check();
        $this->payload = (new Payload($type, $jti, $pti))
            ->addExpTTL($type === JWTTokenType::ACCESS ?
                $this->accessTokenTTL : $this->refreshTokenTTL
            )
            ->setSub($user->getJWTIdentifier())
            ->setIuc($isUsingCookie)
            ->setAtv($atv);

        return JWT::encode(
            array_merge($this->payload->toArray(), $user->getJWTCustomClaims()),
            $this->jwtKey->getPrivateKey(),
            $this->jwtKey->getAlgo()
        );
    }
}
