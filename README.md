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
- [] Implement testing
- [] Implement multi blacklist driver
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

## Configuration config/auth.php

```php
'defaults' => [
    'guard' => 'jwt',
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

***

## Configuration config/jwt.php
Jwt signin using public and private key is first priority, so if you define private and public key, jwt will be signing using this key pairs.
But if you do not define private and public key, jwt will use secret key for signing. If two type key does not exists, it will throw an error.


> [!NOTE]
> Here is available algorithm if you're using secret key
- HS512
- HS256
- HS384
- HS224

> [!NOTE]
> Here is available algorithm if you're using pairs of public and private key
- RS512
- RS256
- RS384
- ES384
- ES256
- ES256K
  
```php
<?php
  /*
    |--------------------------------------------------------------------------
    | JWT Sign in Algorithm
    |--------------------------------------------------------------------------
    |
    | Algorithm for sign jwt token. This token is using encoder and decoder from
    | https://github.com/firebase/php-jwt
    |
    */
    'algo' => env('JWT_ALGO', 'HS256'),


    /*
    |--------------------------------------------------------------------------
    | JWT Private Key
    |--------------------------------------------------------------------------
    |
    | This private key use for first priority of encoding and decoding jwt (signing)
    | so if this key (private key) and (public key) exists, jwt will sign using
    | this key pairs as first priority. If this key pairs does not exist, sign jwt will
    | using jwt secret. If secret does not exist it will throw an error
    |
    */
    "jwt_private_key" => env("JWT_PRIVATE_KEY", null),

    /*
    |--------------------------------------------------------------------------
    | JWT Public Key
    |--------------------------------------------------------------------------
    |
    | This public key is part of key pairs for signing jwt token.
    |
    */
    "jwt_public_key" => env("JWT_PUBLIC_KEY", null),


    /*
    |--------------------------------------------------------------------------
    | JWT Passphrase
    |--------------------------------------------------------------------------
    |
    | This is passphrase use to get jwt private key that translate the key
    | using this passphrase
    |
    */
    "jwt_passphrase" => env("JWT_PASSPHRASE", null),

    /*
    |--------------------------------------------------------------------------
    | Secret
    |--------------------------------------------------------------------------
    |
    | This is secret that used for encoding jwt. This secret use to validate signature
    | Do not expose this jwt secret
    |
    */
    'secret' => env('JWT_SECRET', null),


    /*
    |--------------------------------------------------------------------------
    | Access Token TTL
    |--------------------------------------------------------------------------
    |
    | This is TTL (Time To Life) for access token. When token is expired, the token
    | is already invalid. Access token using to access protected resource.
    | Middleware that can accept this token is auth.jwt:access
    |
    */
    'access_token_ttl' => env('JWT_TTL', 60 * 60),


    /*
    |--------------------------------------------------------------------------
    | Refresh Token TTL
    |--------------------------------------------------------------------------
    |
    | This is TTL (Time To Life) for refresh token. When token is expired, the token
    | is already invalid. Refresh token using to regenerate access token and refresh token
    | and revoke previous access token and refresh token.
    | Middleware that can accept this token is auth.jwt:refresh
    |
    */
    'refresh_token_ttl' => env('JWT_REFRESH_TTL', 60 * 60 * 24 * 7),
```
***

## Implement JWTSubject
You need to implement Iqbalatma\LaravelJwtAuthentication\Interfaces\JWTSubject on User model.
If you would like to add another additional data on jwt claim, you can return array on getJWTCustomClaims
```php
use Iqbalatma\LaravelJwtAuthentication\Interfaces\JWTSubject;
class User extends Authenticatable implements JWTSubject
{
    public function getJWTIdentifier(): string|int
    {
        return $this->getKey();
    }

    public function getJWTCustomClaims(): array
    {
        return [];
    }
}
```
***

## How to use middleware ?
When you are doing authentication, you will receive 2 types token, access and refresh.
Access token use to get protected resource, for example get data product, add new data user, etc.
Access token has shorter ttl, so when access token expired, you can regenerate new token
with refresh token. Endpoint that do refresh token must be protected by middleware type refresh. 
You can see the example on how to implement this middleware bellow
```php
use Illuminate\Support\Facades\Route;

//jwt middleware that need refresh token
Route::post("refresh-token", function (){
    //do refresh logic here
})->middleware("auth.jwt:REFRESH");


//jwt middleware that need access token
Route::middleware("auth.jwt:ACCESS")->group(function () {
    Route::get("user", function () {
        return response()->json([
            "success" => true,
            "user" => Auth::user()
        ]);
    });
    
    // and others route
});


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
```

## Issued Token Service
This is a service related to issued token, access or refresh token. You can get list of issued token with their user-agent or revoke the token

```php
use Iqbalatma\LaravelJwtAuthentication\Services\IssuedTokenService;
use Illuminate\Support\Facades\Auth;

#use to get all issued token
IssuedTokenService::getAllToken(Auth::id());

#use to get all issued refresh token
IssuedTokenService::getAllRefreshToken(Auth::id())

#use to get all issued access token
IssuedTokenService::getAllAccessToken(Auth::id());

#use to revoke refresh token by user agent string name
IssuedTokenService::revokeRefreshTokenByUserAgent('user-agent-name', Auth::id());

#use to revoke access token by user agent string name
IssuedTokenService::revokeAccessTokenByUserAgent('user-agent-name', Auth::id());

#use to revoke both access and refresh token by user agent string name
IssuedTokenService::revokeTokenByUserAgent('user-agent-name', Auth::id());

#use to revoke all token
IssuedTokenService::revokeAllToken(Auth::id());

#use to revoke all token but current token
IssuedTokenService::revokeAllTokenOnOtherUserAgent(Auth::id());
```


