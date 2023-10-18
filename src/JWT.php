<?php

namespace Iqbalatma\LaravelJwtAuthentication;
use Firebase\JWT\JWT as FirebaseJWT;
use Firebase\JWT\Key;

class JWT
{
    private string $key = "example_key";
    private array $payload = [
        'iss' => 'https://example.org',
        'aud' => 'https://example.com',
        'iat' => 1356999524,
        'nbf' => 1357000000
    ];

    public function __construct()
    {
        $encoded = FirebaseJWT::encode($this->payload, $this->key, 'HS256');

//        ddapi($encoded);

        $decoded = FirebaseJWT::decode($encoded."s", new Key($this->key, 'HS256'));
        ddapi($decoded);
    }

}
