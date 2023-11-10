# Laravel JWT Authentication

This is authentication for Laravel with JWT Based. Inspired by [tymondesigns/jwt-auth](https://github.com/tymondesigns/jwt-auth#documentation) and [PHP-Open-Source-Saver/jwt-auth](https://github.com/PHP-Open-Source-Saver/jwt-auth).
This site was built using package from [firebase/php-jwt](https://github.com/firebase/php-jwt) for encode and decode JWT.

***

## Next Feature
This is the lists of next feature
- [x] Using certificates on encode and decode JWT
- [x] Create command console for generate certificates
- [x] Set user on guard login
- [x] Reset user on guard logout
- [x] Add information on config jwt_iqbal
- [x] Rename config from jwt_iqbal into jwt
- [x] Rename guard from jwt-iqbal into jwt
***

## How To Install
This package using syntax and feature that only available on ***php version at least 8.0***

```shell
composer require iqbalatma/laravel-jwt-authentication
```

***

## Publishing Asset
You can publish asset for customization using this command

```shell
php artisan vendor:publish --provider='Iqbalatma\LaravelJwtAuthentication\LaravelJWTAuthenticationProvider'
```

***

## Configuration config/auth.php

```php
'defaults' => [
    'guard' => 'jwt-iqbal',
    'passwords' => 'users',
],


'guards' => [
    ...
    "jwt-iqbal" => [
        "driver" => "jwt-iqbal",
        "provider" => "users"
    ]
],
```

## Configuration config/jwt_iqbal.php
```php
<?php
#token ttl is token lifetime on (seconds)
#so the token will life and valid until ttl finish
return [
    'algo' => env('JWT_ALGO', 'HS256'),
    'secret' => env('JWT_SECRET'),
    'access_token_ttl' => env('JWT_TTL', 60 * 60),
    'refresh_token_ttl' => env('JWT_REFRESH_TTL', 60 * 60 * 24 * 7),
    'latest_incident_time_key' => "jwt.latest_incident_date_time"
];
```

***

## Generate JWT Secret
This is used for generate secret for signing JWT and decoding JWT
```shell
php artisan jwt:secret
```

***

## How to use ?
Here is some available method for authentication

### Authenticate User
This feature used for validate credentials from user request and return back access_token and refresh_token
```php
use Illuminate\Support\Facades\Auth;

$credentials = [
    "email" => "admin@mail.com",
    "password" => "admin"
];

#this attempt method will return boolean when user validation success
Auth::attempt($credentials);

#passing true on second parameter to get return array of access_token and refresh_token
Auth::attempt($credentials, true);
```

### Logout User
This feature used for invalidate and blacklist current authorization token
```php
use Illuminate\Support\Facades\Auth;

Auth::logout();
```

### Refresh Token
This feature used for invalidate access_token and refresh_token and invoke new access_token and refresh_token
```php
use Illuminate\Support\Facades\Auth;

Auth::refreshToken(Auth::user());
```



