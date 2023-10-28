<?php

namespace Iqbalatma\LaravelJwtAuthentication\Models;

use Carbon\Carbon;
use Illuminate\Database\Eloquent\Concerns\HasUuids;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Iqbalatma\LaravelJwtAuthentication\Enums\TokenType;


/**
 * @property string id
 * @property string subject_id
 * @property string jti
 * @property string token_type
 * @property string user_agent
 * @property Carbon created_at
 * @property Carbon updated_at
 */
class IssuedToken extends Model
{
    use HasFactory, HasUuids;
    protected $fillable = [
        "subject_id", "jti", "token_type", "user_agent"
    ];
}
