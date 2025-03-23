<?php

namespace Iqbalatma\LaravelJwtAuthentication\Enums;

use ArchTech\Enums\Values;

enum TokenTypeDeprecated:string
{
    use Values;
    case ACCESS = "access";
    case REFRESH = "refresh";
}
