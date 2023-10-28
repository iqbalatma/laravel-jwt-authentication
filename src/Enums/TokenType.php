<?php

namespace Iqbalatma\LaravelJwtAuthentication\Enums;

enum TokenType:string
{
    case ACCESS = "access";
    case REFRESH = "refresh";
}
