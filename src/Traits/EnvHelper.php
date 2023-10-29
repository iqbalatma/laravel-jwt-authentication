<?php

namespace Iqbalatma\LaravelJwtAuthentication\Traits;

use Closure;
use Illuminate\Support\Str;

/**
 * This env helper is code from Tymon
 */
trait EnvHelper
{

    /**
     * @return bool
     */
    protected function isEnvFileExists(): bool
    {
        return file_exists($this->getEnvFilePath());
    }


    /**
     * @return string
     */
    protected function getEnvFilePath(): string
    {
        if (method_exists($this->laravel, 'environmentFilePath')) {
            return $this->laravel->environmentFilePath();
        }

        return $this->laravel->basePath('.env');
    }

    /**
     * @param string $filepath
     * @return string
     */
    protected function getFileContents(string $filepath): string
    {
        return file_get_contents($filepath);
    }

    /**
     * @param string $filepath
     * @param string $data
     * @return void
     */
    protected function putFileContents(string $filepath, string $data): void
    {
        file_put_contents($filepath, $data);
    }

    /**
     * @param string $key
     * @param string|int $value
     * @param Closure|null $confirmOnExisting
     * @return bool
     */
    public function updateEnvEntry(string $key,string|int $value, Closure $confirmOnExisting = null): bool
    {
        $filepath = $this->getEnvFilePath();

        $fileContents = $this->getFileContents($filepath);

        if (false === Str::contains($fileContents, $key)) {
            // create new entry
            $this->putFileContents(
                $filepath,
                $fileContents.PHP_EOL."{$key}={$value}".PHP_EOL
            );

            return true;
        }

        if (is_null($confirmOnExisting) || $confirmOnExisting()) {
            // update existing entry
            $this->putFileContents(
                $filepath,
                preg_replace(
                    "/{$key}=.*/",
                    "{$key}={$value}",
                    $fileContents
                )
            );

            return true;
        }

        return false;
    }

}
