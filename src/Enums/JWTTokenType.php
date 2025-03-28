<?php

namespace Iqbalatma\LaravelJwtAuthentication\Enums;

use ArchTech\Enums\Names;

enum JWTTokenType
{
    use Names;
    case ACCESS;
    case REFRESH;
}
