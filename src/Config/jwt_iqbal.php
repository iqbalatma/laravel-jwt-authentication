<?php

return [
    'algo' => env('JWT_ALGO', 'HS256'),
    'secret' => env('JWT_SECRET'),
    'access_token_ttl' =>  env('JWT_TTL', 3600),
    'refresh_token_ttl' =>  env('JWT_REFRESH_TTL', 20160),
];
