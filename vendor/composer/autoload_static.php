<?php

// autoload_static.php @generated by Composer

namespace Composer\Autoload;

class ComposerStaticInit18d85af8eeba66ebd6c9a202da861566
{
    public static $prefixLengthsPsr4 = array (
        'I' => 
        array (
            'Iqbalatma\\LaravelJwtAuthentication\\' => 35,
        ),
        'F' => 
        array (
            'Firebase\\JWT\\' => 13,
        ),
    );

    public static $prefixDirsPsr4 = array (
        'Iqbalatma\\LaravelJwtAuthentication\\' => 
        array (
            0 => __DIR__ . '/../..' . '/src',
        ),
        'Firebase\\JWT\\' => 
        array (
            0 => __DIR__ . '/..' . '/firebase/php-jwt/src',
        ),
    );

    public static $classMap = array (
        'Composer\\InstalledVersions' => __DIR__ . '/..' . '/composer/InstalledVersions.php',
    );

    public static function getInitializer(ClassLoader $loader)
    {
        return \Closure::bind(function () use ($loader) {
            $loader->prefixLengthsPsr4 = ComposerStaticInit18d85af8eeba66ebd6c9a202da861566::$prefixLengthsPsr4;
            $loader->prefixDirsPsr4 = ComposerStaticInit18d85af8eeba66ebd6c9a202da861566::$prefixDirsPsr4;
            $loader->classMap = ComposerStaticInit18d85af8eeba66ebd6c9a202da861566::$classMap;

        }, null, ClassLoader::class);
    }
}
