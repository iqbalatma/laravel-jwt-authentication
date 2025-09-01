<?php

namespace Iqbalatma\LaravelJwtAuthentication;

use Illuminate\Contracts\Support\Arrayable;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Str;
use Iqbalatma\LaravelJwtAuthentication\Enums\JWTTokenType;
use Iqbalatma\LaravelJwtAuthentication\Exceptions\JWTMissingRequiredHeaderException;

class Payload implements Arrayable
{
    #issuer : the one who issue this token
    public string $iss;

    #issued at : epoch time when this token is issued
    public int $iat;

    #expired at : epoch time when this token is expired, cannot use anymore
    public int $exp;

    #not valid before : epoch time when this token is start to valid
    public int $nbf;

    #json token identifier : this is unique identifier to this token
    public string $jti;

    #subject : who is the owner of this token
    public string|int|null $sub;

    #issued user agent : user agent that call this token to issued,
    public string $iua;

    #is using cookie :  configuration, for mobile compatibility
    public bool $iuc;

    #type : type of token access or refresh
    public string $type;

    #access token verifier : verifier for access token binding to prevent xss
    public string|null $atv;


    public function __construct(JWTTokenType $tokenType)
    {
        $now = time();
        if (!($userAgent = request()?->userAgent())) {
            throw new JWTMissingRequiredHeaderException("Your request is missing user-agent required header");
        }
        $this->iss = url()->current();
        $this->iat = $now;
        $this->exp = $now;
        $this->nbf = $now;
        $this->jti = Str::uuid();
        $this->sub = null;
        $this->iua = $userAgent;
        $this->iuc = true;
        $this->type = $tokenType->name;
    }

    /**
     * @param int $ttl
     * @return $this
     */
    public function addExpTTL(int $ttl): self
    {
        $this->exp += $ttl;
        return $this;
    }

    /**
     * @param string|int $sub
     * @return $this
     */
    public function setSub(string|int $sub): self
    {
        $this->sub = $sub;
        return $this;
    }


    /**
     * @param bool $iuc
     * @return $this
     */
    public function setIuc(bool $iuc): self
    {
        $this->iuc = $iuc;
        return $this;
    }

    /**
     * @param string $atv
     * @return $this
     */
    public function setAtv(string|null $atv): self
    {
        $this->atv = $this->type === JWTTokenType::ACCESS->name ? Hash::make($atv) : null;
        return $this;
    }

    /**
     * @return array
     */
    public function toArray():array
    {
        return [
            'iss' => $this->iss,
            'iat' => $this->iat,
            'exp' => $this->exp,
            'nbf' => $this->nbf,
            'jti' => $this->jti,
            'sub' => $this->sub,
            'iua' => $this->iua,
            'iuc' => $this->iuc,
            'type' => $this->type,
            'atv' => $this->atv,
        ];
    }
}
