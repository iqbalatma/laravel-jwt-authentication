<?php

namespace Iqbalatma\LaravelJwtAuthentication\Console\Commands;

use Illuminate\Console\Command;
use Illuminate\Support\Str;
use Iqbalatma\LaravelJwtAuthentication\Traits\EnvHelper;

class JWTGenerateSecretCommand extends Command
{
    use EnvHelper;

    /**
     * The name and signature of the console command.
     *
     * @var string
     */
    protected $signature = 'jwt:secret
        {--always-no : Skip generating key if it already exists.}
        {--f|force : Skip confirmation when overwriting an existing key.}
    ';

    /**
     * The console command description.
     *
     * @var string
     */
    protected $description = 'Generates jwt secret';

    /**
     * Execute the console command.
     */
    public function handle(): void
    {
        $this->info("============= GENERATING JWT SECRET ===============");
        $key = Str::random(64);


        if (!$this->isEnvFileExists()) {
            $this->error(".env file does no exists");
            return;
        }

        $updated = $this->updateEnvEntry('JWT_SECRET', $key, function () {
            if ($this->option('always-no')) {
                $this->comment('Secret key already exists.');

                return false;
            }

            if (false === $this->isConfirmed()) {
                $this->comment('No changes were made to your secret key.');

                return false;
            }

            return true;
        });


        if ($updated) {
            $this->updateEnvEntry('JWT_ALGO', 'HS256');
            $this->info("JWT secret $key successfully created");
        }

        /**
         * if env exists, set key into env file
         */
        $this->info("======= GENERATING JWT SECRET SUCCESSFULLY ========");
    }

    /**
     * @return bool
     */
    protected function isConfirmed(): bool
    {
        return $this->option('force') || $this->confirm(
                'This will invalidate all existing tokens. Are you sure you want to override the secret key?'
            );
    }
}
