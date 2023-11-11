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
    "jwt" => [
        "driver" => "jwt",
        "provider" => "users"
    ]
],
```

## Configuration config/jwt_iqbal.php
Jwt signin using public and private key is first priority, so if you define private and public key, jwt will be signing using this key pairs.
But if you do not define private and public key, jwt will use secret key for signing. If two type key does not exists, it will throw an error.


> [!NOTE]
> Here is available algorithm if you using secret key
- HS512
- HS256
- HS384
- HS224

> [!NOTE]
> Here is available algorithm if you using pairs of public and private key
- RS512
- RS256
- RS384
- ES384
- ES256
- ES256K
  
```php
<?php
#token ttl is token lifetime on (seconds)
#so the token will life and valid until ttl finish
return [
    'algo' => env('JWT_ALGO', 'HS256'),
    "jwt_private_key" => env("JWT_PRIVATE_KEY", null),
    "jwt_public_key" => env("JWT_PUBLIC_KEY", null),
    "jwt_passphrase" => env("JWT_PASSPHRASE", null),
    'secret' => env('JWT_SECRET', null),
    'access_token_ttl' => env('JWT_TTL', 60 * 60),
    'refresh_token_ttl' => env('JWT_REFRESH_TTL', 60 * 60 * 24 * 7),
];
```

***

## Generate JWT Credentials
This credential is used for sign jwt token and make sure the token is valid
```shell
php artisan jwt:secret
```
or using pairs of public and secret key
```shell
php artisan jwt:generate-certs
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


### Login By System
This method use for login existing user via authenticable instance
```php
use Illuminate\Support\Facades\Auth;
use App\Models\User;

$user = User::find(1);

Auth::login($user);
```


### Get Token
After login or attempt method triggered and successfully, you can get token access and refresh via guard instance
```php
use Illuminate\Support\Facades\Auth;
use App\Models\User;

$credentials = [
    "email" => "admin@mail.com",
    "password" => "admin"
];

Auth::attempt($credentials);

Auth::getAccessToken();
Auth::getRefreshToken();
```



