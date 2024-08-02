<?php

namespace Test;

use Iqbalatma\LaravelJwtAuthentication\LaravelJWTAuthenticationProvider;

class TestCase extends \Orchestra\Testbench\TestCase
{
    public function setUp(): void
    {
        parent::setUp();
        // additional setup
    }

    /**
     * @param $app
     * @return array
     */
    protected function getPackageProviders($app): array
    {
        return [
            LaravelJWTAuthenticationProvider::class,
        ];
    }
}
