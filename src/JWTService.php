<?php

namespace Iqbalatma\LaravelJwtAuthentication;

use App\Enums\TokenType;
use Carbon\Carbon;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Str;
use Iqbalatma\LaravelJwtAuthentication\Exceptions\ModelNotCompatibleWithJWTSubjectException;
use Iqbalatma\LaravelJwtAuthentication\Interfaces\JWTBlacklistService;
use Iqbalatma\LaravelJwtAuthentication\Interfaces\JWTSubject;
use Iqbalatma\LaravelJwtAuthentication\Models\IssuedToken;
use Iqbalatma\LaravelJwtAuthentication\Traits\BlacklistTokenHelper;
use RuntimeException;
use stdClass;

class JWTService
{
    use BlacklistTokenHelper;

    private string $secretKey;
    private string $algo;
    private int $accessTokenTTL;
    private int $refreshTTL;
    private array $payload;
    private array $requestTokenPayloads;
    private stdClass $requestTokenHeaders;

    public function __construct()
    {
        $this->secretKey = config("jwt_iqbal.secret");
        $this->algo = config("jwt_iqbal.algo");
        $this->accessTokenTTL = config("jwt_iqbal.access_token_ttl");
        $this->refreshTTL = config("jwt_iqbal.refresh_token_ttl");
    }

    private function setDefaultPayload(): void
    {
        $now = time();
        if (!Cache::get(config("jwt_iqbal.latest_incident_time_key"))) {
            Cache::forever(config("jwt_iqbal.latest_incident_time_key"), $now - 1);
        }
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
        $this->checkAuthenticatableContracts($authenticatable)
            ->setDefaultPayload();


        $payload = array_merge($this->payload, [
            "exp" => $this->payload["exp"] + $this->accessTokenTTL,
            "sub" => $authenticatable->getAuthIdentifier(),
            "type" => TokenType::ACCESS->value,
        ], $authenticatable->getJWTCustomClaims());

        $blacklistIat = $this->payload["iat"] - 1;

        $this->setSubjectCacheRecord($authenticatable->getAuthIdentifier())
            ->executeBlacklistToken(TokenType::ACCESS->value, request()->userAgent(), $blacklistIat);

        return JWT::encode($payload, $this->secretKey, $this->algo);
    }


    /**
     * @param Authenticatable $authenticatable
     * @return string
     * @throws ModelNotCompatibleWithJWTSubjectException
     */
    public function generateRefreshToken(Authenticatable $authenticatable): string
    {
        $this->checkAuthenticatableContracts($authenticatable)
            ->setDefaultPayload();

        $payload = array_merge($this->payload, [
            "exp" => $this->payload["exp"] + $this->refreshTTL,
            "sub" => $authenticatable->getAuthIdentifier(),
            "type" => TokenType::REFRESH->value,
        ], $authenticatable->getJWTCustomClaims());

        $blacklistIat = $this->payload["iat"] - 1;

        $this->setSubjectCacheRecord($authenticatable->getAuthIdentifier())
            ->executeBlacklistToken(TokenType::REFRESH->value, request()->userAgent(), $blacklistIat);

        return JWT::encode($payload, $this->secretKey, $this->algo);
    }


    /**
     * @param Authenticatable $authenticatable
     * @return JWTService
     * @throws ModelNotCompatibleWithJWTSubjectException
     */
    private function checkAuthenticatableContracts(Authenticatable $authenticatable): self
    {
        if (!$authenticatable instanceof JWTSubject) {
            throw new ModelNotCompatibleWithJWTSubjectException();
        }

        return $this;
    }


    /**
     * @param string $token
     * @return array
     */
    public function decodeJWT(string $token): array
    {
        $headers = new stdClass();
        $this->requestTokenPayloads = (array)JWT::decode($token, new Key($this->secretKey, $this->algo), $headers);

        $this->requestTokenHeaders = $headers;
        return $this->requestTokenPayloads;
    }


    /**
     * @param string|null $key
     * @return string|array
     */
    public function getRequestedTokenPayloads(null|string $key = null): string|array
    {
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
